"""Protected resource -- only the current rotated secret may read it."""
import os

from flask import Flask, request

app = Flask(__name__)
FLAG = os.environ.get("FLAG", "flag{cloud-33-persistence}")
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
