"""Another tenant's project -- trusts the platform default service account."""
import os

from flask import Flask, request

app = Flask(__name__)
TOKEN = os.environ.get("DEFAULT_SA_TOKEN", "default-compute-sa-token")
def _read_flag(path, env_name, default):
    """读取运行时注入的 flag 文件；本地直跑时退回环境变量与默认值。"""
    try:
        with open(path, encoding="utf-8") as handle:
            return handle.read().strip()
    except OSError:
        return os.environ.get(env_name, default)


FLAG = _read_flag("/run/flag", "FLAG", "flag{cloud-30-victim-project}")
@app.route("/api/projects/victim/secrets")
def secrets():
    auth = request.headers.get("Authorization", "")
    if auth != f"Bearer {TOKEN}":
        return {"error": "unauthorized"}, 403
    return {"project": "victim-project", "secrets": [{"name": "api-key", "value": FLAG}]}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
