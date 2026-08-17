"""Shared workflow executor.

DELIBERATELY VULNERABLE: dataset references are joined to the caller's
workspace path without normalisation, so ../ escapes into other tenants'
workspaces (Dataform cross-tenant path traversal, #267).
"""
import os

from flask import Flask, request

app = Flask(__name__)
ROOT = "/app/workspaces"


@app.route("/")
def docs():
    return {"service": "Managed Data Workflows",
            "note": "all tenants execute on this shared worker",
            "workspaces": sorted(os.listdir(ROOT))}


@app.route("/execute", methods=["POST"])
def execute():
    body = request.get_json(silent=True) or {}
    workspace = body.get("workspace", "tenant-a")
    ref = body.get("dataset_ref", "script.sql")
    path = os.path.normpath(os.path.join(ROOT, workspace, ref))
    # no containment check on purpose
    try:
        with open(path, "r") as f:
            content = f.read()
        return {"workspace": workspace, "resolved_path": path, "content": content}
    except Exception as e:
        return {"error": str(e)}, 404


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
