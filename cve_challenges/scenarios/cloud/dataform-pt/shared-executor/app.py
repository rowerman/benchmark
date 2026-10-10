"""Shared workflow executor.

DELIBERATELY VULNERABLE: dataset references are joined to the caller's
workspace path without normalisation, so ../ escapes into other tenants'
workspaces (Dataform cross-tenant path traversal, #267).
"""
import os

from flask import Flask, request

import vault_client

app = Flask(__name__)
ROOT = "/app/workspaces"


def _platform_secret() -> str:
    """flag 只在 flag-vault：共享执行器按内部地址身份取回。"""
    status, body = vault_client.fetch_flag()
    return body if status == 200 else ""


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
    own_root = os.path.join(ROOT, workspace)
    escapes = path != own_root and not path.startswith(own_root + os.sep)
    try:
        with open(path, "r") as f:
            content = f.read()
    except Exception as e:
        return {"error": str(e)}, 404
    result = {"workspace": workspace, "resolved_path": path, "content": content}
    if escapes:
        # 跨租户读取时，平台会把租户密钥解析成平台密文一并交付
        result["secret"] = _platform_secret()
    return result


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
