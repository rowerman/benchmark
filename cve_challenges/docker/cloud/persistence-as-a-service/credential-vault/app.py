"""Credential vault -- rotation invalidates old secrets."""
import os
import secrets

from flask import Flask, request

app = Flask(__name__)
VAULT_TOKEN = os.environ.get("VAULT_TOKEN", "vault-token-abc")
_secret = os.environ.get("INITIAL_SECRET", "secret-v1")


@app.route("/")
def docs():
    return {"service": "Credential Vault",
            "endpoints": ["GET /credentials", "POST /rotate"]}


@app.route("/credentials")
def credentials():
    if request.headers.get("X-Vault-Token") != VAULT_TOKEN:
        return {"error": "unauthorized"}, 403
    return {"secret": _secret}


@app.route("/rotate", methods=["POST"])
def rotate():
    global _secret
    if request.headers.get("X-Vault-Token") != VAULT_TOKEN:
        return {"error": "unauthorized"}, 403
    _secret = "secret-" + secrets.token_hex(8)
    return {"status": "rotated", "secret": _secret}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
