"""Synapse/ADF control plane -- runtime selection is client-side only."""
import os

import requests
from flask import Flask, request

app = Flask(__name__)
WORKER = os.environ.get("WORKER_URL", "http://ir-worker:5000")

RUNTIMES = {
    "IntegrationRuntime1": "self-hosted (dedicated to your workspace)",
    "AutoResolveIntegrationRuntime": "cloud-hosted (shared multi-tenant pool)",
}


@app.route("/")
def docs():
    return {"service": "Analytics Control Plane", "runtimes": RUNTIMES,
            "note": "runtime is chosen by the client request body"}


@app.route("/pipeline", methods=["POST"])
def pipeline():
    body = request.get_json(silent=True) or {}
    runtime = body.get("runtime_name", "IntegrationRuntime1")
    if runtime == "AutoResolveIntegrationRuntime":
        # forwarded to the shared pool
        try:
            r = requests.post(f"{WORKER}/run", json=body, timeout=15)
            return r.json()
        except Exception as e:
            return {"error": str(e)}, 502
    return {"note": "would run on your dedicated runtime", "runtime": runtime}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
