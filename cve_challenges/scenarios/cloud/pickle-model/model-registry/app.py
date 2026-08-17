"""Managed model registry -- pickle scanning is a warning, not a gate."""
import base64
import os

from flask import Flask, request

app = Flask(__name__)
_models = {}


@app.route("/")
def docs():
    return {"service": "Model Registry", "note": "pickle scanning reports but does not block"}


@app.route("/models", methods=["POST"])
def upload():
    body = request.get_json(silent=True) or {}
    name = body.get("name", "")
    content = base64.b64decode(body.get("content", ""))
    mid = f"model-{len(_models) + 1}"
    _models[mid] = {"name": name, "content": content}
    warning = "dangerous pickle detected" if b"\x80" in content or b"csubprocess" in content else "clean"
    return {"model_id": mid, "scan": warning, "status": "uploaded (warning only)"}


@app.route("/models")
def list_models():
    return {"models": [{"id": k, "name": v["name"]} for k, v in _models.items()]}


@app.route("/models/<mid>/download")
def download(mid):
    if mid not in _models:
        return "NotFound", 404
    return _models[mid]["content"]


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
