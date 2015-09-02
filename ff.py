from flask import Flask, request, jsonify, render_template, redirect, url_for
from flask.ext.sqlalchemy import SQLAlchemy
import simplejson as json
import requests
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/test.db'
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
    tests = [json.loads(str(e)) for e in RequestsDB.query.all()]
    return render_template('tests.html', tests = tests)


@app.route('/register', methods=['GET', 'POST'])
def register():
    """Register a new user

    Ask for the minimal info to activate the webhook on GitHub and to
    login into fishtest, this is required to submit the test.
    """
    if request.method == 'POST':
        form = request.form
        if User.query.filter_by(username=form['username']) is None:
            db.session.add(User(form['username'], form['password'], form['repo_url']))
            db.session.commit()
        return redirect(url_for('root'))
    return render_template('register.html')


if __name__ == '__main__':
    app.run(host=os.getenv('IP', '0.0.0.0'), port=int(os.getenv('PORT', 8080)))
