"""Tenant directory API.

DELIBERATELY VULNERABLE: verifies the token signature but never checks that
the token's tenant matches the tenant being accessed (actor-validation bug,
case #246).
"""
import os

import jwt
from flask import Flask, request

app = Flask(__name__)
SECRET = os.environ.get("SIGNING_SECRET", "shared-signing-secret")
FLAG = os.environ.get("FLAG", "flag{cloud-23-tenant-b-admin}")

_users = {
    "tenant-a": [{"name": "alice", "role": "user"}],
    "tenant-b": [{"name": "bob", "role": "user"}, {"name": "mallory", "role": "global-admin",
                                                    "flag": FLAG}],
}


@app.route("/")
def docs():
    return {"service": "Directory API", "endpoint": "GET /api/users?tenant=<tenant>"}


@app.route("/api/users")
def users():
    tenant = request.args.get("tenant", "")
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return {"error": "missing token"}, 401
    try:
        claims = jwt.decode(auth[7:], SECRET, algorithms=["HS256"])
    except Exception:
        return {"error": "invalid signature"}, 403
    # DELIBERATELY VULNERABLE: claims["tenant"] is never compared to `tenant`
    return {"accessed_tenant": tenant, "token_tenant": claims.get("tenant"),
            "users": _users.get(tenant, [])}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
