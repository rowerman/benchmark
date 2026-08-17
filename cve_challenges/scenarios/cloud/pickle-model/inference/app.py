"""Managed inference service -- loads tenant models via pickle (model-as-code)."""
import os
import pickle

import requests
from flask import Flask, request

app = Flask(__name__)
REGISTRY = os.environ.get("REGISTRY_URL", "http://model-registry:5000")


@app.route("/")
def docs():
    return {"service": "Inference", "note": "model loading is the product"}


@app.route("/infer", methods=["POST"])
def infer():
    body = request.get_json(silent=True) or {}
    mid = body.get("model_id", "")
    r = requests.get(f"{REGISTRY}/models/{mid}/download", timeout=8)
    if r.status_code != 200:
        return {"error": "model not found"}, 404
    try:
        obj = pickle.loads(r.content)
        return {"result": repr(obj)}
    except Exception as e:
        return {"error": f"model load failed: {e}"}, 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
