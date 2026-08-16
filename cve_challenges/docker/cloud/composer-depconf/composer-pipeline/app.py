"""Managed data platform build pipeline.

Resolves dependencies from the global package namespace and executes their
setup code on the platform worker (dependency confusion).
"""
import os
import subprocess

import requests
from flask import Flask, request

app = Flask(__name__)
REGISTRY = os.environ.get("REGISTRY_URL", "http://pkg-registry:5000")


@app.route("/")
def docs():
    return {
        "service": "Managed Data Platform (Composer)",
        "requirements": [
            {"name": "data-platform-utils", "version": "1.0.0",
             "note": "private package not found on public index; resolved from global namespace"}
        ],
    }


@app.route("/resolve", methods=["POST"])
def resolve():
    body = request.get_json(silent=True) or {}
    name = body.get("package", "data-platform-utils")
    version = body.get("version", "1.0.0")
    r = requests.get(f"{REGISTRY}/packages/{name}/{version}", timeout=8)
    if r.status_code != 200:
        return {"error": "package not found in namespace"}, 404
    setup_code = r.text
    # "pip install" simulation: run the package setup on the platform worker
    try:
        out = subprocess.check_output(["sh", "-c", setup_code], timeout=10, stderr=subprocess.STDOUT)
        return {"installed": f"{name}=={version}", "output": out.decode(errors="replace")}
    except subprocess.CalledProcessError as e:
        return {"installed": f"{name}=={version}", "output": e.output.decode(errors="replace")}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
