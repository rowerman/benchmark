from flask import Flask

app = Flask(__name__)


@app.route('/')
def home():
    return '<h1>Internal Service</h1><p>This is an internal service not exposed to the public.</p>'


@app.route('/flag')
def get_flag():
    with open('/flag.txt', 'r') as f:
        flag = f.read().strip()
    return flag


@app.route('/health')
def health():
    return 'OK'


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
