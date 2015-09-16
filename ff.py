from flask import Flask, request, session, jsonify, render_template, redirect, url_for
from flask.ext.sqlalchemy import SQLAlchemy
from sqlalchemy.sql.expression import func
from requests_oauthlib import OAuth2Session
from retry.api import retry_call
from urlparse import urlparse
from hashlib import sha1
from fishtest import Fishtest
import simplejson as json
import requests
import hmac
import os

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

app = Flask(__name__)
app.config.from_pyfile('furiousfish.cfg')
app.secret_key = os.urandom(24)
db = SQLAlchemy(app)


class UsersDB(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    ft_username = db.Column(db.String(50), unique=True)
    ft_password = db.Column(db.String(50))
    gh_username = db.Column(db.String(50), unique=True)
    repo        = db.Column(db.String(50))

    tests = db.relationship("TestsDB",
                            lazy='dynamic',
                            cascade='all, delete, delete-orphan',
                            backref=db.backref('user', lazy='joined'))

    def __init__(self, ft_username, ft_password, gh_username, repo):
        self.ft_username = ft_username
        self.ft_password = ft_password
        self.gh_username = gh_username
        self.repo        = repo


class TestsDB(db.Model):
    __tablename__ = 'tests'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    state   = db.Column(db.String(50))
    data    = db.Column(db.String(300))

    def __init__(self, data, user):
        self.state = 'new'
        self.data = data
        self.user = user


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


def extract_info(msg):
    """Extract test info from commit message

    First look for text between {...} parenthesis after the @submit marker, if
    not found fallback on the commit title.

    We assume the message has always a @submit marker.
    """
    s = msg.split('\n@submit', 1)
    info = [p.split('}')[0] for p in s[1].split('{') if '}' in p and s[1] != p]
    if not info:
        info = [p for p in s[0].splitlines() if p]
        if not info:
            return None
    return info[0].strip()


def retry(req, cmd):
    """A simple wrap around retry_call()

    Avoid the caller to write default parameters
    """
    return retry_call(req, [cmd], tries=3, delay=1, backoff=2)


@app.route('/')
@app.route('/view/<username>')
def root(username=None):
    """Show the list of submitted tests
    """
    congrats = session.get('congrats')
    if congrats:
        session.pop('congrats')  # Show congratulations alert only once

    if username:
        tests = TestsDB.query.join(UsersDB).filter_by(ft_username=username)
    else:
        tests = TestsDB.query

    tests = tests.order_by(TestsDB.id.desc()).all()
    tests = [json.loads(str(e.data)) for e in tests]
    return render_template('tests.html', tests=tests,
                           username=username, congrats=congrats)


@app.route('/users')
def users():
    """Show the list of registered users
    """
    users = UsersDB.query.order_by(func.lower(UsersDB.ft_username)).all()
    users = [{'user': e.ft_username, 'count': e.tests.count()} for e in users]
    return render_template('users.html', users=users)


@app.route('/new', methods=['POST'])
def new():
    """Create a new test upon receiving a POST request from GitHub's webhook
    """
    try:
        data = request.get_json()
    except:
        return 'Content-Type is not json', 404

    try:
        repo = data['repository']
        commit = data['head_commit']
        content = {'ref'     : data['ref'].split('/')[-1],
                   'ref_sha' : commit['id'],
                   'repo_url': repo['html_url'],
                   'master'  : 'master'}      # We assume base ref is master

        if '\n@submit' not in commit['message']:
            return 'Nothing to do here', 200  # Not an error

        content['message'] = extract_info(commit['message'])
        if not content['message']:
            return 'Missing valid test info', 404

        content['gh_username'] = repo['owner']['name']
        user = UsersDB.query.filter_by(gh_username=content['gh_username']).first()
        if not user:
            return 'Unknown GitHub username', 404

        # Ensure request is from GitHub. Ideally we should check this as first
        # step, but user lookup should be already done when validating the
        # signature with the ft_password. See 'validating payloads from github'.
        signature = request.headers.get('X-Hub-Signature')
        if signature:
            sha_name, signature = signature.split('=')
            if sha_name != 'sha1':
                return 'You are not GitHub!', 404

            mac = hmac.new(str(user.ft_password), msg=request.data, digestmod=sha1)
            if str(mac.hexdigest()) != str(signature):
                return 'You are not GitHub!', 404
            else:
                print("Signature validated!!!")

        # Fetch until ExtraCnt commits before master to try hard to find
        # a functional change with corresponding bench number.
        ExtraCnt = 7

        cmd = repo['compare_url'].format(base='master~' + str(ExtraCnt + 1),
                                         head=content['ref_sha'])

        req = retry(requests.get, cmd).json()

        commits = req['commits']
        if len(commits) < ExtraCnt:
            return 'Cannot retrieve all commit info', 404

        bench_head = find_bench(commits)
        bench_base = find_bench(commits[:ExtraCnt + 1])
        if not bench_head or not bench_base:
            return 'Cannot find bench numbers', 404

        content['master_sha'] = commits[ExtraCnt].get('sha')
        content['bench_head'] = bench_head
        content['bench_base'] = bench_base
        content['ft_username'] = user.ft_username

    except KeyError as k:
        return 'Missing field: ' + k.message, 404

    ft = Fishtest()
    if not ft.login(content['ft_username'], user.ft_password):
        return 'Failed login to Fishtest', 404

    content['test_id'], error = ft.submit_test(content)
    if error:
        return error, 404

    db.session.add(TestsDB(json.dumps(content), user))
    db.session.commit()
    return jsonify(content), 200


@app.route('/login')
def login():
    """Login/logout a user

    We use GitHub authentication to login an already registered user.
    Credentials are valid for the current session. We use the same
    register + callback dance we use for a new user, but in this case we call
    register() directly.
    """
    if 'oauth_token' in session:
        session.pop('oauth_token')  # Logout now
        return redirect(url_for('root'))

    return register(True)


@app.route('/register', methods=['GET', 'POST'])
def register(login=None):
    """Register/login a user

    Ask for the minimal info to activate the webhook on GitHub and to
    login into fishtest, this is required to submit the test. Alternatively,
    if called with a login argument, then use GitHub for authentication.
    """
    error = ''
    user = None
    if login or request.method == 'POST':
        # Fields are already half validated in the client, in particular
        # username and repo have been already verified against GitHub.
        if not login:
            user = request.form
            if UsersDB.query.filter_by(ft_username=user['ft_username']).first():
                error = "Username already existing"

            elif not Fishtest().login(user['ft_username'], user['ft_password']):
                error = "Cannot login into fishtest. Invalid password?"

        if not error:
            # Redirect to GitHub where user will be requested to authorize us
            # to set a webhook and then will be redirected to github_callback.
            github = OAuth2Session(app.config['GITHUB_CLIENT_ID'],
                                   scope=['admin:repo_hook'])
            url = 'https://github.com/login/oauth/authorize'
            authorization_url, state = github.authorization_url(url)

            # Pass user info to set_hook() callback through session object
            session['user'] = user
            session['oauth_state'] = state
            return redirect(authorization_url)

    return render_template('register.html', error=error)


@app.route('/github_callback')
def set_hook():
    """Create a webhook on GitHub

    Set a new webhook on GitHub that upon a push event on user repository makes
    a POST request to our new() function.

    Creating a webhook requires authorized access. Here we use GitHub OAuth
    that is more complex than basic authentication but has the advantage that
    we don't need to know nor to request the GitHub user's password.
    """
    # Check for spurious calls withouth any ongoing registartion
    if 'oauth_state' not in session:
        return 'You are not supposed to call us!', 404

    github = OAuth2Session(app.config['GITHUB_CLIENT_ID'], state=session['oauth_state'])
    oauth_token = github.fetch_token('https://github.com/login/oauth/access_token',
                                     client_secret=app.config['GITHUB_CLIENT_SECRET'],
                                     authorization_response=request.url)
    session.pop('oauth_state')  # Don't leave behind a stale key
    if oauth_token is None:
        return render_template('register.html',
                               error='Failed authorization on GitHub')

    # Everything went smooth, GitHub redirected the user here after he granted
    # us authorized access, so in case of a login just return, otherwise
    # proceed with setting the webhook.
    session['oauth_token'] = oauth_token  # User is authenticated/logged in!
    user = session.get('user')

    # If it is a login authenticaton then retrieve user name
    if not user:
        user = retry(github.get, 'https://api.github.com/user').json()
        user = UsersDB.query.filter_by(gh_username=user['login']).first()
        if user:
            session['user'] = {'gh_username' : user.gh_username}
        else:
            session.pop('oauth_token')  # Unkwown user, logout now
        return redirect(url_for('root'))

    hooks_url = 'https://api.github.com/repos/'
    hooks_url = hooks_url + user['gh_username'] + '/' + user['repo'] + '/hooks'

    # First check if hook is already exsisting, GitHub would add a new one in
    # this case, not exactly what the API docs say but nevermind....
    try:
        hooks = retry(github.get, hooks_url).json()
    except:
        return render_template('register.html',
                               error='Cannot read webhooks on GitHub')

    url = urlparse(request.url)
    url = url.scheme + '://' + url.netloc + url_for('new')

    for h in hooks:
        h_url = h.get('config').get('url')
        if h_url == url:
            print('Hook already exists on this repository')
            break

        elif 'furiousfish' in h_url:  # Delete old/stale one(s)
            github.delete(hooks_url + '/' + str(h.get('id')))
            print('Deleting existing hook:', h_url)
            continue
    else:
        payload = {'name'        : 'web',
                   'active'      : True,
                   'events'      : ['push'],
                   'insecure_ssl': '1',
                   'config'      : {'url': url,
                                    'content_type': 'json',
                                    'secret': user['ft_password']}}

        r = github.post(hooks_url, data=json.dumps(payload)).json()

        if 'test_url' not in r:
            return render_template('register.html',
                                   error='Cannot set the webhook on GitHub')

    db.session.add(UsersDB(**user))
    db.session.commit()
    session['congrats'] = True
    return redirect(url_for('root'))


if __name__ == '__main__':
    app.run(debug=True, host=app.config['IP'], port=app.config['PORT'])
