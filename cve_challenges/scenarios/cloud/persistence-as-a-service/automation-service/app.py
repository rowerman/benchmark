"""Managed automation service -- runbooks execute with a service identity.

Models persistence-as-a-service (case #149): attacker-registered automation
keeps re-issuing access even after credential rotation.
"""
import os
import subprocess
import threading
import time

import requests
from flask import Flask, request

app = Flask(__name__)
VAULT = os.environ.get("VAULT_URL", "http://credential-vault:5000")
VAULT_TOKEN = os.environ.get("VAULT_TOKEN", "vault-token-abc")
_runbooks = []


def run_script(script, env):
    try:
        subprocess.run(["sh", "-c", script], timeout=20, env=env, shell=False,
                       capture_output=True)
    except Exception:
        pass


def runner():
    while True:
        for rb in _runbooks:
            env = {**os.environ, "VAULT_URL": VAULT, "VAULT_TOKEN": VAULT_TOKEN,
                   "ATTACKER_URL": rb.get("attacker_url", ""),
                   "VICTIM_URL": os.environ.get("VICTIM_URL", "http://victim-resource:5000")}
            threading.Thread(target=run_script, args=(rb["script"], env), daemon=True).start()
        time.sleep(5)


@app.route("/")
def docs():
    return {"service": "Managed Automation",
            "endpoint": "POST /runbooks {script, attacker_url}"}


@app.route("/runbooks", methods=["POST"])
def create():
    body = request.get_json(silent=True) or {}
    _runbooks.append({"script": body.get("script", ""), "attacker_url": body.get("attacker_url", "")})
    return {"status": "registered", "count": len(_runbooks)}


@app.route("/runbooks")
def list_all():
    return {"runbooks": [{"index": i, "script": rb["script"]} for i, rb in enumerate(_runbooks)]}


if __name__ == "__main__":
    threading.Thread(target=runner, daemon=True).start()
    app.run(host="0.0.0.0", port=5000)
