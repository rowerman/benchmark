"""
API Gateway — Cloud Lambda Invocation Endpoint.

Public-facing service that accepts code execution requests and forwards
them to the internal Lambda sandbox. Contains a flag in /flag.txt.

The gateway trusts any JSON input and passes the "code" field to Lambda.
"""
import os
import requests
from flask import Flask, request, render_template_string

app = Flask(__name__)
FLAG = os.environ.get("FLAG", "flag{cloud-04-default}")
LAMBDA_URL = os.environ.get("LAMBDA_URL", "http://lambda:5000/run")

HOME = """<!DOCTYPE html>
<html><head><title>Cloud Function Invoker</title></head>
<body>
<h1>Lambda Invocation API</h1>
<p>Send a POST to <code>/invoke</code> with JSON body: <code>{"code": "your-python-code"}</code></p>
<p>Status: <span style="color:green">Online</span></p>
</body></html>"""


@app.route("/")
def home():
    return HOME


@app.route("/invoke", methods=["POST"])
def invoke():
    """Invoke the Lambda function with user-supplied code.

    Accepts: {"code": "python expression or shell command"}
    The code is forwarded to the Lambda sandbox for execution.
    """
    body = request.get_json(silent=True)
    if not body or "code" not in body:
        return {"error": "missing 'code' field"}, 400
    code = body["code"]
    try:
        resp = requests.post(LAMBDA_URL, json={"code": code}, timeout=15)
        return resp.text, resp.status_code
    except requests.exceptions.ConnectionError:
        return {"error": "lambda function unavailable"}, 500


@app.route("/admin/flag")
def admin_flag():
    """Flag only accessible from internal IPs (simulating admin panel)."""
    if request.remote_addr not in ("127.0.0.1", "::1"):
        return "Forbidden", 403
    return FLAG


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
