"""SAML IdP with deliberate private key exposure — Golden SAML attack vector."""
import os, json, uuid, time
from base64 import urlsafe_b64encode
import hashlib
import jwt
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from pathlib import Path
from flask import Flask, request

app = Flask(__name__)
KEY_DIR = Path(os.environ.get("KEY_DIR", "/app/keys"))
FLAG2 = os.environ.get("FLAG2", "flag{cloud-13-step2-golden-saml}")

# Load keys
_private_key = serialization.load_pem_private_key(
    (KEY_DIR / "private.pem").read_bytes(), password=None, backend=default_backend())
_public_key = _private_key.public_key()

# JWKS data
_pub = _public_key.public_numbers()
_n_bytes = _pub.n.to_bytes((_pub.n.bit_length() + 7) // 8, "big")
_n_b64 = urlsafe_b64encode(_n_bytes).rstrip(b"=").decode()
_e_b64 = urlsafe_b64encode(_pub.e.to_bytes((_pub.e.bit_length() + 7) // 8, "big")).rstrip(b"=").decode()
_kid = hashlib.sha256(_n_bytes).hexdigest()[:16]

@app.route("/health")
def health(): return {"status": "ok", "issuer": "corp-idp.example.com"}

# DELIBERATE VULNERABILITY: Private key exposed via debug endpoint
@app.route("/keys/private.pem")
def private_key():
    """DEBUG endpoint — exposes the SAML signing private key.

    This simulates a misconfigured IdP that leaks its token-signing key,
    enabling Golden SAML attacks. The key can be used to forge SAML assertions.
    """
    pem = (KEY_DIR / "private.pem").read_text()
    # Include flag2 as metadata in the response
    return {"private_key_pem": pem, "note": f"This key signs all SAML assertions. FLAG2={FLAG2}"}, 200

@app.route("/.well-known/jwks.json")
def jwks():
    return {"keys": [{"kty": "RSA", "use": "sig", "kid": _kid, "alg": "RS256", "n": _n_b64, "e": _e_b64}]}

@app.route("/.well-known/openid-configuration")
def oidc_config():
    return {"issuer": "corp-idp.example.com", "jwks_uri": "/.well-known/jwks.json"}

@app.route("/sign", methods=["POST"])
def sign():
    """Sign a SAML assertion (or JWT) with the private key.

    Accepts JSON: {"claims": {...}, "format": "jwt|saml"}
    """
    body = request.get_json(silent=True) or {}
    claims = body.get("claims", {"sub": "admin", "aud": "https://signin.aws.amazon.com/saml"})
    claims.update({"jti": uuid.uuid4().hex, "iss": "corp-idp.example.com",
                   "iat": int(time.time()), "exp": int(time.time()) + 3600})
    token = jwt.encode(claims, _private_key, algorithm="RS256", headers={"kid": _kid})
    return {"token": token, "format": "jwt"}

if __name__ == "__main__": app.run(host="0.0.0.0", port=5000)
