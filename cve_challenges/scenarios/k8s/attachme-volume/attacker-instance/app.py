"""Attacker-controlled compute instance."""
import os

import requests
from flask import Flask, request

app = Flask(__name__)
API = os.environ.get("API_URL", "http://control-api:5000")
INSTANCE = os.environ.get("INSTANCE_ID", "ocid.instance.9001")


@app.route("/attach", methods=["POST"])
def attach():
    vid = request.args.get("volume_id", "")
    r = requests.post(f"{API}/volumes/{vid}/attach", json={"instance_id": INSTANCE}, timeout=8)
    return r.text, r.status_code


@app.route("/read", methods=["POST"])
def read():
    vid = request.args.get("volume_id", "")
    r = requests.get(f"{API}/volumes/{vid}/data", timeout=8)
    return r.text, r.status_code


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
