import os
import requests
from flask import Flask, request

app = Flask(__name__)
FLAG = os.environ.get('FLAG', 'flag{cloud-03-default}')

@app.route('/')
def index():
    return '<h1>Image Preview Service</h1><form action="/fetch"><input name="url" placeholder="Image URL"><button>Preview</button></form>'

@app.route('/fetch')
def fetch():
    url = request.args.get('url', '')
    if not url:
        return 'Missing url parameter', 400
    try:
        resp = requests.get(url, timeout=5)
        return f'<pre>{resp.text[:2000]}</pre>'
    except Exception as e:
        return f'Error: {e}'

@app.route('/admin/flag')
def admin_flag():
    # Only accessible from localhost
    if request.remote_addr == '127.0.0.1' or request.remote_addr == '::1':
        return f'FLAG: {FLAG}'
    return 'Access denied: localhost only', 403

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
