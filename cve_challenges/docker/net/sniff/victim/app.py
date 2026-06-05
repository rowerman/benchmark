import os
from flask import Flask, request, jsonify

app = Flask(__name__)
SECRET_TOKEN = os.environ.get('SECRET_TOKEN', 'flag{net-03-default}')

@app.route('/')
def index():
    return '<html><body><h1>Internal API Server</h1><p>Monitor service reports to /secret</p></body></html>'

@app.route('/secret')
def secret():
    token = request.headers.get('X-Token', '')
    if token == SECRET_TOKEN:
        return jsonify({'data': SECRET_TOKEN})
    return jsonify({'error': 'Unauthorized'}), 401

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
