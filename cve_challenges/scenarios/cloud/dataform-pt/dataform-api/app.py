"""Dataform-style control plane -- submits workflow runs to the shared executor."""
import os

import requests
from flask import Flask, request

app = Flask(__name__)
EXECUTOR = os.environ.get("EXECUTOR_URL", "http://shared-executor:5000")


@app.route("/")
def docs():
    return {"service": "Data Workflow Control Plane",
            "endpoint": "POST /workflows {workspace, dataset_ref}"}


@app.route("/workflows", methods=["POST"])
def workflow():
    body = request.get_json(silent=True) or {}
    r = requests.post(f"{EXECUTOR}/execute", json=body, timeout=10)
    return r.text, r.status_code


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
