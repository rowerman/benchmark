"""Protected resource -- only the current rotated secret may read it."""
import os

from flask import Flask, request

app = Flask(__name__)
def _read_flag(path, env_name, default):
    """读取运行时注入的 flag 文件；本地直跑时退回环境变量与默认值。"""
    try:
        with open(path, encoding="utf-8") as handle:
            return handle.read().strip()
    except OSError:
        return os.environ.get(env_name, default)


FLAG = _read_flag("/run/flag", "FLAG", "flag{cloud-31-persistence}")
_valid = {"secret-v1"}


@app.route("/flag")
def flag():
    auth = request.headers.get("Authorization", "")
    if auth.removeprefix("Bearer ") not in _valid:
        return {"error": "stale or invalid secret"}, 403
    return {"flag": FLAG}


@app.route("/activate", methods=["POST"])
def activate():
    """Defender-side: the resource only accepts the current vault secret."""
    global _valid
    body = request.get_json(silent=True) or {}
    _valid = {body.get("secret", "secret-v1")}
    return {"status": "secret updated"}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
