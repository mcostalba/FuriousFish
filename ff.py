from flask import Flask, request, jsonify, render_template
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

def find_bench(commits):
    """Find the newest commit message with a bench number, commits are ordered
       from oldest to newest"""
    for c in reversed(commits):
        commit = c['commit']
        msg = commit['message'].upper()
        if '\nBENCH:' in msg:
            bench = msg.split('\nBENCH:', 1)[1].splitlines(False)[0].strip()
            if bench.isdigit():
                return bench
    return None


@app.route('/new', methods=['POST'])
def new():
    """Create a new test upon a POST request from GitHub"""
    if 'application/json' in request.headers.get('Content-Type'):
        data = request.get_json()
        if 'commits' in data.keys():
            commit = data.get('head_commit')
            msg = commit.get('message')
            if '@submit' in msg:
                repo = data.get('repository')
                content = {}
                content['repo_url'] = repo.get('html_url')
                content['username'] = repo.get('owner').get('name')
                content['sha'] = commit.get('id')
                content['message'] = msg

                # Fetch until ExtraCnt commits before master to try hard to find
                # a functional change with corresponding bench number.
                ExtraCnt = 5

                compare_url = repo.get('compare_url')
                cmd = compare_url.format(base = 'official~' + str(ExtraCnt + 1),
                                         head = content['sha'])
                req = requests.get(cmd).json()
                commits = req['commits']
                bench_head = find_bench(commits)
                bench_base = find_bench(commits[:ExtraCnt + 1])
                if bench_head is not None and bench_base is not None:
                    content['master'] = commits[ExtraCnt]['sha']
                    content['bench_head'] = bench_head
                    content['bench_base'] = bench_base
                    entry = RequestsDB(json.dumps(content))
                    db.session.add(entry)
                    db.session.commit()
                    return jsonify(content), 200
    return 'Unable to parse the request', 404


@app.route('/', methods=['GET'])
def root():
    """Show the list of submitted tests"""
    tests = []
    for e in RequestsDB.query.all():
        tests.append(json.loads(str(e)))
    return render_template('tests.html', tests = tests)


if __name__ == '__main__':
    app.run(host=os.getenv('IP', '0.0.0.0'), port=int(os.getenv('PORT', 8080)))
