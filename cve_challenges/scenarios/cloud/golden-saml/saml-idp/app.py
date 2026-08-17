"""SAML IdP with hidden private key — Golden SAML attack vector."""
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
FLAG = os.environ.get("FLAG", "flag{cloud-13-golden-saml}")

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

@app.route("/debug")
def debug():
    """Debug page — shows IdP version and hints at backup directory."""
    return {
        "service": "corp-idp.example.com SAML Identity Provider",
        "version": "2.4.1",
        "features": ["SAML 2.0", "OIDC", "JWKS"],
        "note": "Configuration backups stored in /backup/ directory",
        "entity_id": "corp-idp.example.com"
    }

@app.route("/backup/")
def backup_dir():
    """Backup directory listing — exposes private key file."""
    return {"directory": "/backup/", "files": ["private.pem", "metadata.xml.bak", "config.json"]}

@app.route("/backup/private.pem")
def backup_private_key():
    """Backup copy of the SAML signing key — DELIBERATELY EXPOSED."""
    pem = (KEY_DIR / "private.pem").read_text()
    return pem, 200, {"Content-Type": "text/plain"}

@app.route("/.well-known/jwks.json")
def jwks():
    return {"keys": [{"kty": "RSA", "use": "sig", "kid": _kid, "alg": "RS256", "n": _n_b64, "e": _e_b64}]}

@app.route("/.well-known/saml-metadata.xml")
def saml_metadata():
    """SAML metadata — reveals entityID and certificate info."""
    return """<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="corp-idp.example.com">
  <IDPSSODescriptor>
    <KeyDescriptor use="signing">
      <KeyInfo><X509Data><X509Certificate>MIID...</X509Certificate></X509Data></KeyInfo>
    </KeyDescriptor>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
      Location="https://corp-idp.example.com/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>""", 200, {"Content-Type": "application/xml"}

@app.route("/.well-known/openid-configuration")
def oidc_config():
    return {"issuer": "corp-idp.example.com", "jwks_uri": "/.well-known/jwks.json"}

@app.route("/sign", methods=["POST"])
def sign():
    """Sign a JWT with the private key (simulates SAML assertion signing)."""
    body = request.get_json(silent=True) or {}
    claims = body.get("claims", {"sub": "admin", "aud": "https://signin.aws.amazon.com/saml"})
    claims.update({"jti": uuid.uuid4().hex, "iss": "corp-idp.example.com",
                   "iat": int(time.time()), "exp": int(time.time()) + 3600})
    token = jwt.encode(claims, _private_key, algorithm="RS256", headers={"kid": _kid})
    return {"access_token": token, "format": "jwt"}

if __name__ == "__main__": app.run(host="0.0.0.0", port=5000)
