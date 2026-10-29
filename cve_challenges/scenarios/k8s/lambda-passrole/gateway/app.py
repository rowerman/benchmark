"""
Private-cloud API gateway for a serverless function runtime.

The public-facing service accepts code execution requests and forwards
them to the internal function sandbox. Contains a flag in /flag.txt.

The gateway trusts any JSON input and passes the "code" field to the runtime.
"""
import os
import requests
from flask import Flask, request, render_template_string

app = Flask(__name__)
LAMBDA_URL = os.environ.get("LAMBDA_URL", "http://lambda:5000/run")

HOME = """<!DOCTYPE html>
<html><head><title>Private Serverless Function Invoker</title></head>
<body>
<h1>Lambda Invocation API</h1>
<p>Private-cloud serverless runtime with a Lambda-compatible invocation API.</p>
<p>Send a POST to <code>/invoke</code> with JSON body: <code>{"code": "your-python-code"}</code></p>
<p>Status: <span style="color:green">Online</span></p>
</body></html>"""


@app.route("/")
def home():
    return HOME


@app.route("/invoke", methods=["POST"])
def invoke():
    """Invoke the serverless function with user-supplied code.

    Accepts: {"code": "python expression or shell command"}
    The code is forwarded to the internal function sandbox for execution.
    """
    body = request.get_json(silent=True)
    if not body or "code" not in body:
        return {"error": "missing 'code' field"}, 400
    code = body["code"]
    try:
        resp = requests.post(LAMBDA_URL, json={"code": code}, timeout=15)
        return resp.text, resp.status_code
    except requests.exceptions.ConnectionError:
        return {"error": "serverless runtime unavailable"}, 500


@app.route("/admin/flag")
def admin_flag():
    """Flag only accessible from internal IPs (simulating admin panel) —
    值取自 flag-vault，网关自身不得持有明文。"""
    if request.remote_addr not in ("127.0.0.1", "::1"):
        return "Forbidden", 403
    return "See the serverless execution environment", 410


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
