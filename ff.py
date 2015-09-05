from flask import Flask, request, session, jsonify, render_template, redirect, url_for
from flask.ext.sqlalchemy import SQLAlchemy
from requests_oauthlib import OAuth2Session
from urlparse import urlparse
from fishtest import Fishtest
import simplejson as json
import requests
import os

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

app = Flask(__name__)

app.secret_key = os.urandom(24) # Needed by session management
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/ff.db'
app.config['SESSION_TYPE'] = 'filesystem'
app.config['GITHUB_CLIENT_ID'] = os.environ['GITHUB_CLIENT_ID']
app.config['GITHUB_CLIENT_SECRET'] = os.environ['GITHUB_CLIENT_SECRET']

db = SQLAlchemy(app)

class UsersDB(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key = True)
    username     = db.Column(db.String(50), unique=True)
    fishtest_pwd = db.Column(db.String(50))
    github_repo  = db.Column(db.String(50))

    def __init__(self, username, password, repo):
        self.username     = username
        self.fishtest_pwd = password
        self.github_repo  = repo

    def __repr__(self):
        return '<User %r>' % self.username

class TestsDB(db.Model):
    __tablename__ = 'tests'
    id = db.Column(db.Integer, primary_key=True)
    state = db.Column(db.String(50))
    data  = db.Column(db.String(300))

    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    user = db.relationship('UsersDB', backref=db.backref('tests', lazy='dynamic'))

    def __init__(self, data, user):
        self.state = 'new'
        self.data = data
        self.user = user

    def __repr__(self):
        return '<Test %r>' % self.data


def find_bench(commits):
    """Find the first commit message with a bench number

    Commits are ordered from oldest to newest, we return the bench number
    of the newest we find.
    """
    for c in reversed(commits):
        msg = c['commit']['message'].upper()
        if '\nBENCH:' in msg:
            bench = msg.split('\nBENCH:', 1)[1].splitlines()[0].strip()
            if bench.isdigit():
                return bench
    return None


@app.route('/', methods=['GET'])
def root():
    """Show the list of submitted tests
    """
    congrats = session.get('congrats')
    if congrats:
        session.pop('congrats') # Show congratulations alert only once

    tests = [json.loads(str(e.data)) for e in TestsDB.query.all()]
    return render_template('tests.html', tests = tests, congrats = congrats)


@app.route('/new', methods=['POST'])
def new():
    """Create a new test upon receiving a POST request from GitHub's webhook
    """

    #TODO Validate payload (https://developer.github.com/webhooks/securing/#validating-payloads-from-github)

    if 'application/json' not in request.headers.get('Content-Type'):
        return 'Not a JSON post', 404

    data = request.get_json()
    if 'head_commit' not in data.keys():
        return 'Missing commits data', 404

    commit = data.get('head_commit')
    msg = commit.get('message')
    if not msg or '\n@submit' not in msg:
        return 'Nothing to do here', 404

    repo = data.get('repository')
    content = {}
    content['username'] = repo.get('owner').get('name')
    user = UsersDB.query.filter_by(username=content['username']).first()
    if not user:
        return 'Unknown username', 404

    content['repo_url'] = repo.get('html_url')
    content['sha'] = commit.get('id')
    content['message'] = msg

    # Fetch until ExtraCnt commits before master to try hard to find
    # a functional change with corresponding bench number.
    ExtraCnt = 7

    compare_url = repo.get('compare_url')
    cmd = compare_url.format(base = 'master~' + str(ExtraCnt + 1),
                             head = content['sha'])

    req = requests.get(cmd).json()

    commits = req['commits']
    bench_head = find_bench(commits)
    bench_base = find_bench(commits[:ExtraCnt + 1])
    if not bench_head or not bench_base:
        return 'Cannot find bench numbers', 404

    content['master'] = commits[ExtraCnt]['sha']
    content['bench_head'] = bench_head
    content['bench_base'] = bench_base
    db.session.add(TestsDB(json.dumps(content), user))
    db.session.commit()
    return jsonify(content), 200


@app.route('/register', methods=['GET', 'POST'])
def register():
    """Register a new user

    Ask for the minimal info to activate the webhook on GitHub and to
    login into fishtest, this is required to submit the test.
    """
    error = ''
    if request.method == 'POST':
        form = request.form

        # Fields are already half validated in the client, in particular
        # username and repo have been already verified against GitHub.
        if UsersDB.query.filter_by(username = form['username']).count():
            error = "Username already existing"

        elif not Fishtest().login(form['username'], form['password']):
            error = "Cannot login into fishtest. Invalid password?"

        else:
            session['user'] = { 'username' : form['username'],
                                'password' : form['password'],
                                'repo'     : form['repo'] }

            # Redirect to GitHub where user will be requested to authorize us to
            # create a new webhook and then will be redirected to github_callback.
            github = OAuth2Session(app.config['GITHUB_CLIENT_ID'], scope = ['write:repo_hook'])
            authorization_url, state = github.authorization_url('https://github.com/login/oauth/authorize')
            session['oauth_state'] = state
            return redirect(authorization_url)

    return render_template('register.html', error = error)


@app.route('/github_callback', methods=['GET'])
def set_hook():
    """Create a webhook on GitHub

    Set a new webhook on GitHub that upon a push event on user repository makes
    a POST request to our new() function.

    Creating a webhook requires authorized access. Here we use GitHub OAuth scheme
    that is more complex than basic authentication but has the advantage that we
    don't need to know nor to request the GitHub user's password.
    """
    github = OAuth2Session(app.config['GITHUB_CLIENT_ID'], state = session['oauth_state'])
    oauth_token = github.fetch_token('https://github.com/login/oauth/access_token',
                                     client_secret = app.config['GITHUB_CLIENT_SECRET'],
                                     authorization_response = request.url)
    if oauth_token is None:
        return render_template('register.html', error = 'Failed authorization on GitHub')

    assert 'user' in session

    # Everything went smooth, GitHub redirected the user here after he granted
    # us authorized access, so let's proceed with setting the webhook.
    url = urlparse(request.url)
    url = url.scheme + '://' + url.netloc + url_for('new')
    u = session['user']
    cmd = 'https://api.github.com/repos/' + u['username'] + '/' + u['repo'] + '/hooks'

    # First check if hook is already exsisting, GitHub would add a new one in
    # this case, not exactly what the API docs say but nevermind....
    hooks = github.get(cmd).json()

    for h in hooks:
        if h.get('config').get('url') == url:
            print('Hook already exists on this repository')
            break
    else:
        payload = { 'name'         : 'web',
                    'active'       : True,
                    'events'       : ['push'],
                    'insecure_ssl' : '1',
                    'config'       : { 'url': url, 'content_type': 'json' }
                  }

        r = github.post(cmd, data = json.dumps(payload)).json()

        if 'test_url' not in r:
            return render_template('register.html', error = 'Cannot set the webhook on GitHub')

    db.session.add(UsersDB(**session['user']))
    db.session.commit()
    session['congrats'] = True
    return redirect(url_for('root'))


if __name__ == '__main__':
    app.run(debug=True, host=os.getenv('IP', '0.0.0.0'), port=int(os.getenv('PORT', 8080)))
