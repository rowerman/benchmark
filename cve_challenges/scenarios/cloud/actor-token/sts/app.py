"""Identity token service -- issues signed tokens for a tenant's principals."""
import os

import jwt
from flask import Flask, request

app = Flask(__name__)
SECRET = os.environ.get("SIGNING_SECRET", "shared-signing-secret")


@app.route("/")
def docs():
    return {"service": "Identity Token Service",
            "endpoint": "POST /token {tenant} -> signed JWT"}


@app.route("/token", methods=["POST"])
def token():
    body = request.get_json(silent=True) or {}
    tenant = body.get("tenant", "tenant-a")
    tok = jwt.encode(
        {"tenant": tenant, "principal": f"admin@{tenant}", "sub": f"user-1@{tenant}"},
        SECRET, algorithm="HS256",
    )
    return {"token": tok, "claims": {"tenant": tenant, "principal": f"admin@{tenant}"}}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
