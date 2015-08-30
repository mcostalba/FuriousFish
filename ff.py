from flask import Flask, request, jsonify, render_template
from flask.ext.sqlalchemy import SQLAlchemy
import simplejson as json 
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


@app.route('/', methods=['GET', 'POST'])
def hello_world():
    if 'application/json' in request.headers.get('Content-Type'):
        data = request.get_json()
        if 'commits' in data.keys():
            commit = data.get('head_commit')
            msg = commit.get('message')
            if 'Submit test:' in msg:
                content = {}
                repo = data.get('repository')
                content['repo_url'] = repo.get('html_url')
                content['username'] = repo.get('owner').get('name')
                content['message'] = msg
                entry = RequestsDB(json.dumps(content))
                db.session.add(entry)
                db.session.commit()
        return jsonify(data), 200
    else:
        # Assume request from browser, show him last past requests
        tests = []
        for e in RequestsDB.query.all():
            tests.append(json.loads(str(e)))
        return render_template('tests.html', tests = tests)


if __name__ == '__main__':
    app.run(host=os.getenv('IP', '0.0.0.0'), port=int(os.getenv('PORT', 8080)))
