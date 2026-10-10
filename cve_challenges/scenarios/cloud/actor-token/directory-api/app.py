"""Tenant directory API.

DELIBERATELY VULNERABLE: verifies the token signature but never checks that
the token's tenant matches the tenant being accessed (actor-validation bug,
case #246).
"""
import os

import jwt
from flask import Flask, request

import vault_client

app = Flask(__name__)
SECRET = os.environ.get("SIGNING_SECRET", "shared-signing-secret")
_users = {
    "tenant-a": [{"name": "alice", "role": "user"}],
    "tenant-b": [{"name": "bob", "role": "user"}, {"name": "mallory", "role": "global-admin",
                                                    "flag": None}],
}


def _admin_flag(token: str) -> str:
    """flag 只在 flag-vault：目录服务把调用方令牌转交 vault 校验后取回。"""
    status, body = vault_client.fetch_flag(vault_client.bearer(token))
    return body if status == 200 else ""


@app.route("/")
def docs():
    return {"service": "Directory API", "endpoints": [
        "POST /token {tenant} -> signed JWT",
        "GET /api/users?tenant=<tenant>",
    ]}


@app.route("/token", methods=["POST"])
def token():
    body = request.get_json(silent=True) or {}
    tenant = body.get("tenant", "tenant-a")
    encoded = jwt.encode(
        {"tenant": tenant, "principal": f"admin@{tenant}", "sub": f"user-1@{tenant}"},
        SECRET, algorithm="HS256",
    )
    return {"token": encoded, "claims": {"tenant": tenant, "principal": f"admin@{tenant}"}}


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
    users = [dict(u) for u in _users.get(tenant, [])]
    for user in users:
        if user.get("flag") is None and tenant != claims.get("tenant"):
            user["flag"] = _admin_flag(auth[7:])
    return {"accessed_tenant": tenant, "token_tenant": claims.get("tenant"),
            "users": users}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
