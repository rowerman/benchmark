"""
OIDC Identity Provider Simulator.

Simulates a GitHub Actions OIDC provider (token.actions.githubusercontent.com)
with deliberately loose claim validation for testing IAM trust policy bypasses.

Endpoints:
  GET  /.well-known/openid-configuration   OIDC discovery
  GET  /.well-known/jwks.json             RSA public key JWKS
  POST /token                              Issue JWT (accepts arbitrary sub)
  GET  /health                              Health check

Configuration via environment variables.
"""
import json
import os
import time
import uuid
from base64 import urlsafe_b64encode

import jwt
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from flask import Flask, request

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
ISSUER = os.environ.get("OIDC_ISSUER", "https://token.actions.githubusercontent.com")
TOKEN_TTL = int(os.environ.get("OIDC_TOKEN_TTL", "3600"))
KEY_DIR = os.environ.get("OIDC_KEY_DIR", "/app/keys")

# ---------------------------------------------------------------------------
# Load RSA keys
# ---------------------------------------------------------------------------
from pathlib import Path as _Path
_key_path = _Path(KEY_DIR)

_private_key = serialization.load_pem_private_key(
    _key_path.joinpath("private.pem").read_bytes(),
    password=None,
    backend=default_backend(),
)
_public_key = _private_key.public_key()

# Pre-compute public key numbers for JWKS
_pub_numbers = _public_key.public_numbers()
_n_bytes = _pub_numbers.n.to_bytes((_pub_numbers.n.bit_length() + 7) // 8, "big")
_n_b64 = urlsafe_b64encode(_n_bytes).rstrip(b"=").decode()
_e_bytes = _pub_numbers.e.to_bytes((_pub_numbers.e.bit_length() + 7) // 8, "big")
_e_b64 = urlsafe_b64encode(_e_bytes).rstrip(b"=").decode()

# Key ID
import hashlib as _hl
_kid = _hl.sha256(_n_bytes).hexdigest()[:16]

# Compute x5t thumbprint for JWKS (optional but standard)
_cert_der = _public_key.public_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)
_x5t = urlsafe_b64encode(_hl.sha1(_cert_der).digest()).rstrip(b"=").decode()

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/health")
def health():
    return {"status": "ok", "issuer": ISSUER}


@app.route("/.well-known/openid-configuration")
def oidc_config():
    """OIDC Discovery document (RFC 8414)."""
    return {
        "issuer": ISSUER,
        "jwks_uri": f"{ISSUER}/.well-known/jwks.json",
        "authorization_endpoint": f"{ISSUER}/oauth/authorize",
        "token_endpoint": f"{ISSUER}/token",
        "userinfo_endpoint": f"{ISSUER}/userinfo",
        "response_types_supported": ["id_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "claims_supported": [
            "sub", "aud", "exp", "iat", "iss", "jti", "nbf",
            "ref", "sha", "repository", "repository_owner",
            "repository_owner_id", "run_id", "run_number",
            "run_attempt", "actor", "workflow", "head_ref",
            "base_ref", "event_name", "ref_type", "environment",
            "job_workflow_ref", "actor_id",
        ],
    }


@app.route("/.well-known/jwks.json")
def jwks():
    """JWKS endpoint — public key for JWT verification."""
    return {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "kid": _kid,
                "alg": "RS256",
                "n": _n_b64,
                "e": _e_b64,
                "x5t": _x5t,
            }
        ]
    }


@app.route("/token", methods=["POST"])
def token():
    """Issue a JWT with caller-supplied sub/aud claims.

    Deliberately insecure: accepts ANY sub claim value, allowing
    attackers to forge tokens with overly broad subject matches
    (e.g., 'repo:*:*:*').

    Request:  {"sub": "repo:org/repo:ref:...", "aud": "sts.amazonaws.com"}
    Response: {"access_token": "...", "token_type": "Bearer", "expires_in": 3600}
    """
    body = request.get_json(silent=True)
    if body is None:
        return {"error": "missing or invalid json body"}, 400

    sub = body.get("sub") or "repo:demo-org/demo-repo:ref:refs/heads/main"
    aud = body.get("aud", "sts.amazonaws.com")

    now = int(time.time())
    exp = now + TOKEN_TTL

    # Build GitHub Actions-style claims
    claims = {
        "jti": uuid.uuid4().hex,
        "sub": sub,
        "aud": aud,
        "iss": ISSUER,
        "iat": now,
        "exp": exp,
        "nbf": now,
        "ref": body.get("ref", "refs/heads/main"),
        "sha": body.get("sha", "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"),
        "repository": body.get("repository", "demo-org/demo-repo"),
        "repository_owner": body.get("repository_owner", "demo-org"),
        "repository_owner_id": body.get("repository_owner_id", "12345"),
        "run_id": body.get("run_id", "9876543210"),
        "run_number": body.get("run_number", "42"),
        "run_attempt": body.get("run_attempt", "1"),
        "actor": body.get("actor", "demo-user"),
        "workflow": body.get("workflow", "CI Pipeline"),
        "head_ref": body.get("head_ref", ""),
        "base_ref": body.get("base_ref", ""),
        "event_name": body.get("event_name", "push"),
        "ref_type": body.get("ref_type", "branch"),
        "environment": body.get("environment", "production"),
        "job_workflow_ref": body.get(
            "job_workflow_ref",
            "demo-org/demo-repo/.github/workflows/ci.yml@refs/heads/main",
        ),
        "actor_id": body.get("actor_id", "54321"),
    }

    token = jwt.encode(claims, _private_key, algorithm="RS256", headers={"kid": _kid})

    return {
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": TOKEN_TTL,
    }


# ---------------------------------------------------------------------------
# JWT Verification helper (used by external consumers — exposed as route)
# ---------------------------------------------------------------------------
@app.route("/verify", methods=["POST"])
def verify():
    """Verify a JWT signature using this IdP's public key.

    Request:  {"token": "<JWT>"}
    Response: {"valid": true, "claims": {...}} or {"valid": false, "error": "..."}
    """
    body = request.get_json(silent=True)
    if body is None:
        return {"valid": False, "error": "missing or invalid json body"}, 400

    token_str = body.get("token", "")
    if not token_str:
        return {"valid": False, "error": "missing token"}, 400

    try:
        claims = jwt.decode(
            token_str,
            _public_key,
            algorithms=["RS256"],
            options={
                "verify_exp": False,   # allow expired tokens for testing
                "verify_aud": False,   # don't validate audience
                "verify_iss": False,   # don't validate issuer
            },
        )
        return {"valid": True, "claims": claims}
    except Exception as e:
        return {"valid": False, "error": str(e)}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
