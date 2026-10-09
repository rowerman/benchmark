"""EKS-style cluster API -- node role can mint tokens and list secrets."""
import os

from flask import Flask, request

app = Flask(__name__)
TOKEN = os.environ.get("NODE_TOKEN", "node-session-token")
def _read_flag(path, env_name, default):
    """读取运行时注入的 flag 文件；本地直跑时退回环境变量与默认值。"""
    try:
        with open(path, encoding="utf-8") as handle:
            return handle.read().strip()
    except OSError:
        return os.environ.get(env_name, default)


FLAG = _read_flag("/run/flag", "FLAG", "flag{cloud-19-cluster-secrets}")
@app.route("/secrets")
def secrets():
    auth = request.headers.get("Authorization", "")
    if auth != f"Bearer {TOKEN}":
        return {"error": "unauthorized"}, 403
    return {"secrets": [{"name": "db-password", "data": "s3cr3t"},
                        {"name": "flag", "data": FLAG}]}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
