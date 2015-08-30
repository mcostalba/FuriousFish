from flask import Flask, request, jsonify
from flask.ext.sqlalchemy import SQLAlchemy

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
            commits = data.get('commits')
            last = commits[-1]
            msg = last.get('message')
            if 'Submit test:' in msg:
                content = []
                repo = data.get('repository')
                repo_url = repo.get('html_url')
                content.append(repo_url)
                content.append(msg)
                entry = RequestsDB('\n'.join(content))
                db.session.add(entry)
                db.session.commit()
        return jsonify(data), 200
    else:
        # Assume request from browser, show him last past requests
        content = []
        all = RequestsDB.query.all()
        for e in all:
            content.append(str(e))
        return '\n'.join(content), 200


if __name__ == '__main__':
    app.run()
