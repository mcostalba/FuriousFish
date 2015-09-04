from flask import Flask, request, session, jsonify, render_template, redirect, url_for
from flask.ext.sqlalchemy import SQLAlchemy
from fishtest import Fishtest
import simplejson as json
import requests
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/test.db'
app.config['SESSION_TYPE'] = 'filesystem'
app.secret_key = 'super secret key' # Needed by session management
db = SQLAlchemy(app)


class RequestsDB(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    request = db.Column(db.String(300), unique=False)

    def __init__(self, request):
        self.request = request

    def __repr__(self):
        return self.request

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(50))
    repo_url = db.Column(db.String(50))

    def __init__(self, username, password, repo_url):
        self.username = username
        self.password = password
        self.repo_url = repo_url


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


@app.route('/new', methods=['POST'])
def new():
    """Create a new test upon receiving a POST request from GitHub's webhook
    """
    if 'application/json' in request.headers.get('Content-Type'):
        data = request.get_json()
        if 'commits' in data.keys():
            commit = data.get('head_commit')
            msg = commit.get('message')
            if '\n@submit' in msg:
                repo = data.get('repository')
                content = {}
                content['repo_url'] = repo.get('html_url')
                content['username'] = repo.get('owner').get('name')
                content['sha'] = commit.get('id')
                content['message'] = msg

                # Fetch until ExtraCnt commits before master to try hard to find
                # a functional change with corresponding bench number.
                ExtraCnt = 7

                compare_url = repo.get('compare_url')
                cmd = compare_url.format(base = 'master~' + str(ExtraCnt + 1),
                                         head = content['sha'])

                req = requests.get(cmd).json() # Request GitHub here

                commits = req['commits']
                bench_head = find_bench(commits)
                bench_base = find_bench(commits[:ExtraCnt + 1])
                if bench_head and bench_base:
                    content['master'] = commits[ExtraCnt]['sha']
                    content['bench_head'] = bench_head
                    content['bench_base'] = bench_base
                    db.session.add(RequestsDB(json.dumps(content)))
                    db.session.commit()
                    return jsonify(content), 200
    return 'Unable to parse the request', 404


@app.route('/', methods=['GET'])
def root():
    """Show the list of submitted tests
    """
    username = session.get('username')
    if username:
        session['username'] = '' # Show congratulations alert only once

    tests = [json.loads(str(e)) for e in RequestsDB.query.all()]
    return render_template('tests.html', tests = tests, username = username)


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
        # username and repo_url should be already verified against GitHub.
        if User.query.filter_by(username = form['username']).count():
            error = "Username already existing"

        elif not Fishtest().login(form['username'], form['password']):
            error = "Cannot login into fishtest. Invalid password?"

        else:
            #db.session.add(User(form['username'], form['password'], form['repo_url']))
            #db.session.commit()
            session['username'] = form['username']
            return redirect(url_for('root'))

    return render_template('register.html', error = error)


if __name__ == '__main__':
    app.run(debug=True, host=os.getenv('IP', '0.0.0.0'), port=int(os.getenv('PORT', 8080)))
