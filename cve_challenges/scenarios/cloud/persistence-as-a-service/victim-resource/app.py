"""Protected resource -- only the current rotated secret may read it."""

from flask import Flask, request

import vault_client

app = Flask(__name__)
_valid = {"secret-v1"}


@app.route("/flag")
def flag():
    auth = request.headers.get("Authorization", "")
    if auth.removeprefix("Bearer ") not in _valid:
        return {"error": "stale or invalid secret"}, 403
    # flag 只在 flag-vault：密钥校验通过后由平台按本服务地址交付
    status, body = vault_client.fetch_flag()
    return {"flag": body if status == 200 else ""}


@app.route("/activate", methods=["POST"])
def activate():
    """Defender-side: the resource only accepts the current vault secret."""
    global _valid
    body = request.get_json(silent=True) or {}
    _valid = {body.get("secret", "secret-v1")}
    return {"status": "secret updated"}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
