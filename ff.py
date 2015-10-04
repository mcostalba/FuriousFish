from flask import Flask, flash, request, session, jsonify, render_template, redirect, url_for
from flask.ext.sqlalchemy import SQLAlchemy
from sqlalchemy.sql.expression import func
from requests_oauthlib import OAuth2Session
from retry.api import retry_call
from urlparse import urlparse
from hashlib import sha1
from fishtest import Fishtest, FishtestError
import simplejson as json
import requests
import hmac
import os
import re

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

    def __init__(self, user):
        self.ft_username = user['ft_username']
        self.ft_password = user['ft_password']
        self.gh_username = user['gh_username']
        self.repo        = user['repo']

    def to_dict(self):
        return {'ft_username': self.ft_username,
                'ft_password': self.ft_password,
                'gh_username': self.gh_username,
                'repo'       : self.repo}


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


def retry(req, cmd):
    """A simple wrapper around retry_call()

    Avoid the caller to write all the retry parameters
    """
    return retry_call(req, [cmd], tries=3, delay=1, backoff=2)


def find_bench(commits):
    """Find the first commit message with a bench number

    Commits are ordered from oldest to newest, we return the bench number
    of the newest we find.
    """
    p = r'^[\s]*bench[:\s]*(\d+)'
    for c in reversed(commits):
        msg = c['commit']['message']
        bench = re.search(p, msg, re.MULTILINE | re.IGNORECASE)
        if bench:
            return bench.group(1)
    return None


def extract_info(msg):
    """Extract test info from commit message

    First look for text between {...} parenthesis after the @submit marker, if
    not found fallback on the commit title.
    """
    for p in [r'^@submit\s*{\s*(.+?)\s*}', r'^\s*(.+?)\s*$.*?@submit']:
        info = re.search(p, msg, re.MULTILINE | re.DOTALL)
        if info:
            return info.group(1)
    return None


@app.route('/')
@app.route('/view/<username>')
def root(username=None):
    """Show the list of submitted tests
    """
    if username:
        tests = TestsDB.query.join(UsersDB).filter_by(ft_username=username)
    else:
        tests = TestsDB.query

    tests = tests.order_by(TestsDB.id.desc()).all()
    tests = [json.loads(str(e.data)) for e in tests]
    return render_template('tests.html', tests=tests, username=username)


@app.route('/users')
def users():
    """Show the list of registered users
    """
    users = UsersDB.query.order_by(func.lower(UsersDB.ft_username)).all()
    users = [{'user': e.ft_username, 'count': e.tests.count()} for e in users]
    return render_template('users.html', users=users)


@app.route('/delete/user')
@app.route('/delete/user/<username>')
def delete(username=None):
    """Delete a registered user
    """
    if username and 'login' in session:
        user = UsersDB.query.filter_by(ft_username=username).first()
        if user and username == session['login']['user']['ft_username']:
            db.session.delete(user)
            db.session.commit()
            session.pop('login')  # Logout because user is deleted
            flash("User " + username + " deleted!", "ok")
        else:
            flash("You cannot delete another user")
    return ""


@app.route('/incoming', methods=['POST'])
def incoming():
    """Update test result

       When a test finishes, Fishtest sends an email with the result to a
       Google group that forwards it to its subscribers. Among them there is
       an email address belonging to a webhook service that, upon receiving the
       mail, forwards it here through a POST request. A bit complex but the
       bottom line is we receive a timely update as soon as a test finishes and
       we use this info to update the corresponding row in TestsDB.
    """
    try:
        msg = request.get_json()['plain']
        p = r'^http://tests.stockfishchess.org/tests/view/(.+)'
        test_id = re.search(p, msg).group(1)
        r = r'^TC.+D: \d+'
        result = re.search(r, msg, re.MULTILINE | re.DOTALL)
        if not result:
            return 'Nothing to do', 200  # Different kind of test
        result = result.group(0)
    except:
        return 'Cannot parse message', 404

    for t in TestsDB.query.filter(TestsDB.state != 'finished').all():
        content = json.loads(t.data)
        if content['test_id'] == test_id:
            content['result'] = result
            t.data = json.dumps(content)
            t.state = 'finished'
            db.session.commit()

    return 'ok', 200


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
        msg = commit['message']

        if '\n@submit' not in msg:
            return 'Nothing to do here', 200  # Not an error

        info = extract_info(msg)
        if not info:
            return 'Missing valid test info', 404

        owner = repo['owner']['name']
        user = UsersDB.query.filter_by(gh_username=owner).first()
        if not user:
            return 'Unknown GitHub username', 404

        # Ensure request is from GitHub. Ideally we should check this as first
        # step, but user lookup should be already done when validating the
        # signature with ft_password. See 'validating payloads from github'.
        signature = request.headers.get('X-Hub-Signature')
        if signature:
            sha_name, signature = signature.split('=')
            if sha_name != 'sha1':
                return 'You are not GitHub!', 404

            mac = hmac.new(str(user.ft_password), msg=request.data, digestmod=sha1)
            if str(mac.hexdigest()) != str(signature):
                return 'You are not GitHub!', 404

        # Fetch until ExtraCnt commits before master to try hard to find
        # a functional change with corresponding bench number.
        ExtraCnt = 7

        cmd = repo['compare_url'].format(base='master~' + str(ExtraCnt + 1),
                                         head=commit['id'])

        req = retry(requests.get, cmd).json()

        commits = req['commits']
        if len(commits) < ExtraCnt:
            return 'Cannot retrieve all commit info', 404

        bench_head = find_bench(commits)
        bench_base = find_bench(commits[:ExtraCnt + 1])
        if not bench_head or not bench_base:
            return 'Cannot find bench numbers', 404

        ft = Fishtest()
        ft.login(user.ft_username, user.ft_password)

        content = {'ref': data['ref'].split('/')[-1],
                   'ref_sha': commit['id'],
                   'repo_url': repo['html_url'],
                   'master': 'master',               # We assume base is master
                   'master_sha': commits[ExtraCnt].get('sha'),
                   'bench_head': bench_head,
                   'bench_base': bench_base,
                   'message': info,
                   'ft_username': user.ft_username}  # To easy tests view page

        content['test_id'] = ft.submit_test(content)

    except (KeyError, TypeError) as e:
        return 'Missing field: ' + e.message, 404
    except FishtestError as e:
        return 'Fishtest: ' + e.message, 404

    db.session.add(TestsDB(json.dumps(content), user))
    db.session.commit()
    return jsonify(content), 200


@app.route('/login')
def login():
    """Login/logout a user

    We use GitHub authentication to login an already registered user.
    Credentials are valid for the current session.
    """
    if request.referrer:
        next = urlparse(request.referrer).path  # No external redirects
    else:
        next = url_for('root')

    if 'login' not in session:
        return redirect(github_oauth(next))

    session.pop('login')  # Logout now!
    return redirect(next)


@app.route('/register', methods=['GET', 'POST'])
def register():
    """Register a new user

    Ask for the minimal info to activate the webhook on GitHub and to login
    into fishtest, this is required to submit the test.
    """
    if request.method == 'POST':
        # Fields are already half validated in the client, in particular
        # username and repo have been already verified against GitHub.
        user = request.form
        if UsersDB.query.filter_by(ft_username=user['ft_username']).first():
            flash("Username already existing")

        elif not Fishtest().login(user['ft_username'], user['ft_password']):
            flash("Cannot login into Fishtest. Invalid password?")

        else:
            session['user'] = user
            return redirect(github_oauth(url_for('users')))

    return render_template('register.html')


def github_oauth(next):
    """ Authenticate with GitHub

    Redirect to GitHub where user will be requested to authorize us and then he
    will be redirected to github_callback. This is more complex than basic
    authentication but has the advantage that we don't need to know nor to
    request the GitHub user's password.

    This function is called both for registering a new user and for signing in.

    NOTE: For some reason the actual redirect() should be done at the calling
    function. If done here nothing happens!
    """
    url = 'https://github.com/login/oauth/authorize'
    client_id = app.config['GITHUB_CLIENT_ID']
    github = OAuth2Session(client_id, scope=['admin:repo_hook'])
    authorization_url, state = github.authorization_url(url)
    session['oauth_state'] = state
    session['next'] = next
    return authorization_url


@app.route('/github_callback')
def github_callback():
    """Finalize GitHub authentication

    We are called from GitHub at the end of the OAuth process, after the user
    has possibly authorized us.
    """
    if 'oauth_state' not in session or 'next' not in session:
        return 'You are not supposed to call us!', 404

    url = 'https://github.com/login/oauth/access_token'
    client_id = app.config['GITHUB_CLIENT_ID']
    secret = app.config['GITHUB_CLIENT_SECRET']
    github = OAuth2Session(client_id, state=session['oauth_state'])
    session.pop('oauth_state')  # Don't leave behind a stale key
    oauth_token = github.fetch_token(url,
                                     client_secret=secret,
                                     authorization_response=request.url)
    if not oauth_token:
        flash('Failed authorization on GitHub')

    elif 'user' not in session:
        finalize_login(github, oauth_token)

    elif set_hook(github, session['user']):
        db.session.add(UsersDB(session['user']))
        db.session.commit()
        session.pop('user')
        flash('Congratulations! You have completed your registration', 'ok')

    next = session['next']
    session.pop('next')
    return redirect(next)


def finalize_login(github, oauth_token):
    """Set the user as logged in

    After a succesful authentication process, lookup the user in our DB and
    change his state as logged in. OAuth2 is username agonstic, only after
    validation we can ask GitHub for the actual username.
    """
    req = retry(github.get, 'https://api.github.com/user').json()
    user = UsersDB.query.filter_by(gh_username=req['login']).first()
    if user:
        session['login'] = {'user': user.to_dict(), 'oauth_token': oauth_token}
    else:
        flash('Unkwown user: ' + req['login'])


def set_hook(github, user):
    """Create a webhook on GitHub

    Set a new webhook on GitHub that upon a push event on user repository makes
    a POST request to our new() function.
    """
    hooks_url = 'https://api.github.com/repos/'
    hooks_url = hooks_url + user['gh_username'] + '/' + user['repo'] + '/hooks'
    try:
        hooks = retry(github.get, hooks_url).json()

        our_url = urlparse(request.url)
        our_url = our_url.scheme + '://' + our_url.netloc + url_for('new')
        for h in hooks:
            h_url = h['config']['url']
            if h_url == our_url:
                break

            elif 'furiousfish' in h_url:  # Delete old/stale one(s)
                github.delete(hooks_url + '/' + str(h['id']))
                continue
        else:
            payload = {'name': 'web',
                       'active': True,
                       'events': ['push'],
                       'insecure_ssl': '1',
                       'config': {'url': our_url,
                                  'content_type': 'json',
                                  'secret': user['ft_password']}}

            r = github.post(hooks_url, data=json.dumps(payload)).json()
            if 'test_url' not in r:
                flash('Cannot set the webhook on GitHub')
                return False
    except:
        flash('Error while accessing webhooks on GitHub')
        return False

    return True


if __name__ == '__main__':
    app.run(debug=True, host=app.config['IP'], port=app.config['PORT'])
