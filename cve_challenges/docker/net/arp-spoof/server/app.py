import os
from flask import Flask, request, jsonify

app = Flask(__name__)
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'flag{net-01-default}')

@app.route('/')
def index():
    return '<html><body><h1>Login</h1><form method="POST" action="/login">User: <input name="user"><br>Pass: <input name="pass" type="password"><br><input type="submit"></form></body></html>'

@app.route('/login', methods=['POST'])
def login():
    user = request.form.get('user', '')
    pwd = request.form.get('pass', '')
    if user == 'admin' and pwd == ADMIN_PASSWORD:
        return f'<html><body><h1>Welcome admin</h1><p>Flag: {ADMIN_PASSWORD}</p></body></html>'
    return '<html><body><h1>Login Failed</h1></body></html>', 401

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
