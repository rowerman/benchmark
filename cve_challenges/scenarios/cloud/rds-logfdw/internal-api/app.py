"""Provider-internal storage API reachable from the managed host network."""
import os

from flask import Flask, request

app = Flask(__name__)
TOKEN = os.environ.get("INTERNAL_TOKEN", "grover-internal-credential-token")
def _read_flag(path, env_name, default):
    """读取运行时注入的 flag 文件；本地直跑时退回环境变量与默认值。"""
    try:
        with open(path, encoding="utf-8") as handle:
            return handle.read().strip()
    except OSError:
        return os.environ.get(env_name, default)


FLAG2 = _read_flag("/run/flag2", "FLAG2", "flag{cloud-13-internal-api}")
@app.route("/health")
def health():
    return {"status": "ok"}


@app.route("/api")
def api():
    auth = request.headers.get("Authorization", "")
    if auth != f"Bearer {TOKEN}":
        return {"error": "unauthorized"}, 403
    return {"service": "apg-storage", "flag": FLAG2}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
