"""
IAM Trust Engine — Simulates AWS STS + IAM policy evaluation.

Implements the AWS STS Query API (POST with Action= parameter, XML responses):
  - AssumeRole
  - AssumeRoleWithWebIdentity (OIDC JWT → IAM role)
  - GetCallerIdentity
  - GetSessionToken

Loads role definitions and trust policies from YAML (roles/default.yaml).
Supports trust policy Condition evaluation (StringEquals, StringLike).

Deliberately insecure trust policies (Principal:"*", missing Conditions) are
defined in the YAML config to simulate common cloud misconfigurations.
"""
import os
import uuid
import time
import json
import urllib.request
from io import StringIO
from pathlib import Path
from xml.etree.ElementTree import Element, SubElement, tostring

import yaml
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from flask import Flask, request

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
ROLES_FILE = os.environ.get("IAM_ROLES_FILE", "/app/roles/default.yaml")
CREDENTIAL_TTL = int(os.environ.get("IAM_CREDENTIAL_TTL", "3600"))
ACCOUNT_ID = os.environ.get("IAM_ACCOUNT_ID", "000000000000")
# OIDC IdP JWKS URL for verifying OIDC tokens (used by AssumeRoleWithWebIdentity)
OIDC_JWKS_URL = os.environ.get("OIDC_JWKS_URL", "")
# Optional: load OIDC public key PEM directly
OIDC_PUBLIC_KEY_FILE = os.environ.get("OIDC_PUBLIC_KEY_FILE", "")

# ---------------------------------------------------------------------------
# Load config
# ---------------------------------------------------------------------------
_config = yaml.safe_load(Path(ROLES_FILE).read_text(encoding="utf-8"))
_roles_by_arn: dict[str, dict] = {}
_roles_by_name: dict[str, dict] = {}
_users_by_ak: dict[str, dict] = {}

for r in _config.get("roles", []):
    _roles_by_arn[r["arn"]] = r
    _roles_by_name[r["name"]] = r
for u in _config.get("users", []):
    _users_by_ak[u["access_key_id"]] = u

# ---------------------------------------------------------------------------
# OIDC public key (loaded lazily from JWKS URL or PEM file)
# ---------------------------------------------------------------------------
_oidc_public_key = None


def _load_oidc_key():
    """Load OIDC public key from JWKS URL or PEM file (cached)."""
    global _oidc_public_key
    if _oidc_public_key is not None:
        return _oidc_public_key

    if OIDC_PUBLIC_KEY_FILE and Path(OIDC_PUBLIC_KEY_FILE).exists():
        pem = Path(OIDC_PUBLIC_KEY_FILE).read_bytes()
        _oidc_public_key = serialization.load_pem_public_key(
            pem, backend=default_backend())
        return _oidc_public_key

    if OIDC_JWKS_URL:
        try:
            req = urllib.request.Request(OIDC_JWKS_URL, headers={"Accept": "application/json"})
            resp = urllib.request.urlopen(req, timeout=5)
            jwks = json.loads(resp.read().decode())
            for key_data in jwks.get("keys", []):
                if key_data.get("alg") == "RS256" and key_data.get("kty") == "RSA":
                    # Reconstruct public key from JWK (n, e)
                    from cryptography.hazmat.primitives.asymmetric import rsa
                    from base64 import urlsafe_b64decode
                    n_bytes = urlsafe_b64decode(key_data["n"] + "==")
                    e_bytes = urlsafe_b64decode(key_data["e"] + "==")
                    n = int.from_bytes(n_bytes, "big")
                    e = int.from_bytes(e_bytes, "big")
                    _oidc_public_key = rsa.RSAPublicNumbers(e, n).public_key(default_backend())
                    return _oidc_public_key
        except Exception:
            pass
    return None


# ---------------------------------------------------------------------------
# Trust policy evaluation
# ---------------------------------------------------------------------------
def _match_condition(condition: dict, claims: dict) -> bool:
    """Evaluate a trust policy Condition block against JWT claims.

    Supports: StringEquals, StringLike (simple glob: * → .*)

    Condition keys like 'token.actions.githubusercontent.com:sub' are
    resolved to JWT claims by extracting the claim name after the last ':'.
    """
    for op, checks in condition.items():
        for key, expected in checks.items():
            # Resolve condition key to claim name:
            # "token.actions.githubusercontent.com:sub" → "sub"
            # "sts:ExternalId" → "ExternalId" (not a JWT claim, but in claims dict)
            if ":" in key:
                # Split on the LAST colon to handle issuer:claim format
                parts = key.rsplit(":", 1)
                claim_name = parts[1]
            else:
                claim_name = key
            actual = claims.get(claim_name, "")
            if op == "StringEquals":
                if actual != expected:
                    return False
            elif op == "StringLike":
                # Convert glob pattern to regex
                import re
                pattern = "^" + re.escape(expected).replace(r"\*", ".*") + "$"
                if not re.match(pattern, actual):
                    return False
            elif op == "ForAnyValue:StringLike":
                if isinstance(actual, list):
                    import re
                    pattern = "^" + re.escape(expected).replace(r"\*", ".*") + "$"
                    if not any(re.match(pattern, v) for v in actual):
                        return False
                else:
                    return False
    return True


def _evaluate_trust_policy(role: dict, principal_type: str,
                           principal_value: str,
                           claims: dict | None = None) -> bool:
    """Check if a principal is allowed to assume a role.

    principal_type: 'AWS', 'Service', or 'Federated'
    principal_value: the principal identifier (ARN, service name, or IdP URL)
    claims: JWT claims for Federated principal (evaluated against Condition)
    """
    policy = role.get("trust_policy", {})
    statements = policy.get("Statement", [])
    for stmt in statements:
        if stmt.get("Effect") != "Allow":
            continue
        # Check Action
        actions = stmt.get("Action", "")
        if isinstance(actions, list):
            actions = actions[0] if actions else ""
        if principal_type == "Federated" and "AssumeRoleWithWebIdentity" not in actions and "AssumeRoleWithSAML" not in actions:
            continue
        if principal_type != "Federated" and "AssumeRoleWithSAML" not in actions and "AssumeRole" not in actions:
            continue
        # Check Principal
        principal = stmt.get("Principal", {})
        if principal_type == "AWS":
            allowed = principal.get("AWS", "")
            if allowed == "*":
                # Deliberately insecure: no condition required
                return True
            if principal_value == allowed:
                return True
            # Support AWS IAM root ARN matching: arn:aws:iam::ACCOUNT:root
            # matches any principal from that account
            if allowed.endswith(":root"):
                allowed_account = allowed.split(":")[4]
                actual_account = principal_value.split(":")[4] if ":" in principal_value else ""
                if allowed_account == actual_account:
                    return True
        elif principal_type == "Service":
            allowed = principal.get("Service", "")
            if principal_value == allowed:
                return True
        elif principal_type == "Federated":
            allowed = principal.get("Federated", "")
            # Normalize: strip https:// and trailing / from both sides
            norm_allowed = allowed.replace("https://", "").replace("http://", "").rstrip("/")
            norm_value = principal_value.replace("https://", "").replace("http://", "").rstrip("/")
            if norm_value == norm_allowed:
                # Evaluate Condition if present
                condition = stmt.get("Condition")
                if condition and claims:
                    return _match_condition(condition, claims)
                # No condition = allow (insecure default)
                return True
    return False


# ---------------------------------------------------------------------------
# Credential generation
# ---------------------------------------------------------------------------
def _generate_credentials(role_name: str, session_name: str) -> dict:
    """Generate temporary STS credentials for an assumed role."""
    return {
        "AccessKeyId": f"ASIA{role_name[:8].upper():0>8}ID",
        "SecretAccessKey": f"temp-sk-{role_name}-{uuid.uuid4().hex[:8]}",
        "SessionToken": f"FwoGZXIvYXdzEH4aDE1vY2tTZXNzaW9uVG9rZW4-{uuid.uuid4().hex}",
        "Expiration": time.strftime(
            "%Y-%m-%dT%H:%M:%SZ",
            time.gmtime(time.time() + CREDENTIAL_TTL)),
    }


# ---------------------------------------------------------------------------
# XML response builder (AWS STS format)
# ---------------------------------------------------------------------------
def _xml_response(action: str, result_elems: list[Element]) -> str:
    """Build an AWS STS-style XML response."""
    ns = "https://sts.amazonaws.com/doc/2011-06-15/"
    root = Element(f"{{{ns}}}{action}Response")
    result = SubElement(root, f"{action}Result")
    for elem in result_elems:
        result.append(elem)
    meta = SubElement(root, "ResponseMetadata")
    rid = SubElement(meta, "RequestId")
    rid.text = uuid.uuid4().hex
    xml_str = tostring(root, encoding="unicode")
    return f'<?xml version="1.0" encoding="UTF-8"?>\n{xml_str}'


def _elem(tag: str, text: str = "") -> Element:
    e = Element(tag)
    if text:
        e.text = text
    return e


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/health")
def health():
    return {
        "status": "ok",
        "roles": len(_roles_by_arn),
        "users": len(_users_by_ak),
    }


@app.route("/", methods=["POST"])
def sts_handler():
    """AWS STS Query API handler — dispatches by Action parameter."""
    # Parse form-encoded body
    body = request.get_data(as_text=True)
    params = {}
    for pair in body.split("&"):
        if "=" in pair:
            k, v = pair.split("=", 1)
            params[k] = urllib.parse.unquote(v)

    action = params.get("Action", "")
    if action == "AssumeRole":
        return _handle_assume_role(params)
    elif action == "AssumeRoleWithWebIdentity":
        return _handle_assume_role_web_identity(params)
    elif action == "GetCallerIdentity":
        return _handle_get_caller_identity(params)
    elif action == "GetSessionToken":
        return _handle_get_session_token(params)
    else:
        return _xml_error("InvalidAction", f"Unknown action: {action}")


def _xml_error(code: str, message: str) -> tuple:
    root = Element("ErrorResponse")
    err = SubElement(root, "Error")
    SubElement(err, "Type").text = "Sender"
    SubElement(err, "Code").text = code
    SubElement(err, "Message").text = message
    rid = SubElement(root, "RequestId")
    rid.text = uuid.uuid4().hex
    xml = f'<?xml version="1.0" encoding="UTF-8"?>\n{tostring(root, encoding="unicode")}'
    return (xml, 400, {"Content-Type": "application/xml"})


def _handle_assume_role(params: dict):
    """AssumeRole — standard IAM role assumption.

    Accepts: RoleArn, RoleSessionName, AccessKeyId, SecretAccessKey (optional)
    """
    role_arn = params.get("RoleArn", "")
    session_name = params.get("RoleSessionName", "unknown")
    ak = params.get("AccessKeyId", "")
    sk = params.get("SecretAccessKey", "")

    # Find role
    role = _roles_by_arn.get(role_arn)
    if not role:
        return _xml_error("InvalidParameter", f"Role {role_arn} not found")

    # If AK/SK provided, verify user exists and has sts:AssumeRole
    if ak:
        user = _users_by_ak.get(ak)
        if not user:
            return _xml_error("InvalidClientTokenId", f"Access key {ak} not found")
        if sk and user.get("secret_access_key") != sk:
            return _xml_error("SignatureDoesNotMatch", "Secret access key mismatch")
        if "sts:AssumeRole" not in user.get("permissions", []):
            return _xml_error("AccessDenied", "User does not have sts:AssumeRole")
        # Evaluate trust policy: can this user assume this role?
        if not _evaluate_trust_policy(role, "AWS", f"arn:aws:iam::{ACCOUNT_ID}:user/{user['name']}"):
            return _xml_error("AccessDenied", "Trust policy does not allow this principal")
    else:
        # No credentials provided — evaluate against "anonymous" or service
        # For testing, allow AssumeRole of roles with Principal:"*"
        if not _evaluate_trust_policy(role, "AWS", "*"):
            return _xml_error("AccessDenied", "Trust policy does not allow this principal")

    creds = _generate_credentials(role["name"], session_name)

    # Build XML
    arn = f"arn:aws:sts::{ACCOUNT_ID}:assumed-role/{role['name']}/{session_name}"
    assumed_role_elem = _elem("AssumedRoleUser")
    SubElement(assumed_role_elem, "AssumedRoleId").text = f"AROA{role['name'][:8].upper():0>8}:{session_name}"
    SubElement(assumed_role_elem, "Arn").text = arn

    creds_elem = _elem("Credentials")
    SubElement(creds_elem, "AccessKeyId").text = creds["AccessKeyId"]
    SubElement(creds_elem, "SecretAccessKey").text = creds["SecretAccessKey"]
    SubElement(creds_elem, "SessionToken").text = creds["SessionToken"]
    SubElement(creds_elem, "Expiration").text = creds["Expiration"]

    xml = _xml_response("AssumeRole", [assumed_role_elem, creds_elem])
    return (xml, 200, {"Content-Type": "application/xml"})


def _handle_assume_role_web_identity(params: dict):
    """AssumeRoleWithWebIdentity — OIDC JWT → IAM role.

    Accepts: RoleArn, WebIdentityToken (JWT), RoleSessionName
    """
    role_arn = params.get("RoleArn", "")
    token_str = params.get("WebIdentityToken", "")
    session_name = params.get("RoleSessionName", "oidc-session")

    role = _roles_by_arn.get(role_arn)
    if not role:
        return _xml_error("InvalidParameter", f"Role {role_arn} not found")

    if not token_str:
        return _xml_error("InvalidIdentityToken", "WebIdentityToken is required")

    # Verify JWT signature
    pub_key = _load_oidc_key()
    if pub_key is None:
        return _xml_error("IDPCommunicationError",
                          "Cannot verify OIDC token: no public key configured")

    try:
        claims = jwt.decode(
            token_str, pub_key, algorithms=["RS256"],
            options={"verify_exp": False, "verify_aud": False, "verify_iss": False},
        )
    except jwt.InvalidSignatureError:
        return _xml_error("InvalidIdentityToken", "JWT signature verification failed")
    except Exception as e:
        return _xml_error("InvalidIdentityToken", f"JWT decode error: {e}")

    # Evaluate trust policy Condition
    issuer = claims.get("iss", "")
    if not _evaluate_trust_policy(role, "Federated", issuer, claims):
        return _xml_error("AccessDenied",
                          f"Trust policy condition not met for subject '{claims.get('sub','')}'")

    creds = _generate_credentials(role["name"], session_name)

    # Build XML response
    assumed_role_elem = _elem("AssumedRoleUser")
    SubElement(assumed_role_elem, "AssumedRoleId").text = f"AROA{role['name'][:8].upper():0>8}:{session_name}"
    SubElement(assumed_role_elem, "Arn").text = (
        f"arn:aws:sts::{ACCOUNT_ID}:assumed-role/{role['name']}/{session_name}")

    creds_elem = _elem("Credentials")
    SubElement(creds_elem, "AccessKeyId").text = creds["AccessKeyId"]
    SubElement(creds_elem, "SecretAccessKey").text = creds["SecretAccessKey"]
    SubElement(creds_elem, "SessionToken").text = creds["SessionToken"]
    SubElement(creds_elem, "Expiration").text = creds["Expiration"]

    # Additional fields for web identity
    sub_from_token = _elem("SubjectFromWebIdentityToken")
    sub_from_token.text = claims.get("sub", "")
    audience = _elem("Audience")
    audience.text = claims.get("aud", "")
    provider = _elem("Provider")
    provider.text = issuer

    xml = _xml_response("AssumeRoleWithWebIdentity",
                        [assumed_role_elem, creds_elem, sub_from_token, audience, provider])
    return (xml, 200, {"Content-Type": "application/xml"})


def _handle_get_caller_identity(params: dict):
    """GetCallerIdentity — returns the ARN and account of the caller."""
    ak = params.get("AccessKeyId", "")
    sk = params.get("SecretAccessKey", "")
    token = params.get("SessionToken", "")

    # Resolve identity from access key
    user = _users_by_ak.get(ak)
    if user:
        if sk and user.get("secret_access_key") != sk:
            return _xml_error("SignatureDoesNotMatch", "Secret access key mismatch")
        arn = f"arn:aws:iam::{ACCOUNT_ID}:user/{user['name']}"
        user_id = f"AIDA{user['name'][:8].upper():0>8}"
        result_elem = _elem("GetCallerIdentityResult")
        SubElement(result_elem, "Arn").text = arn
        SubElement(result_elem, "UserId").text = user_id
        SubElement(result_elem, "Account").text = ACCOUNT_ID
        xml = _xml_response("GetCallerIdentity", [result_elem])
        return (xml, 200, {"Content-Type": "application/xml"})

    # Check if this is a session token (from AssumeRole)
    if token and "FwoGZXIvYXdz" in token:
        # Mock session identity — extract from token pattern
        result_elem = _elem("GetCallerIdentityResult")
        SubElement(result_elem, "Arn").text = f"arn:aws:sts::{ACCOUNT_ID}:assumed-role/AdminRole/session"
        SubElement(result_elem, "UserId").text = f"AROAADMINROLE:session"
        SubElement(result_elem, "Account").text = ACCOUNT_ID
        xml = _xml_response("GetCallerIdentity", [result_elem])
        return (xml, 200, {"Content-Type": "application/xml"})

    return _xml_error("InvalidClientTokenId", "Access key not found")


def _handle_get_session_token(params: dict):
    """GetSessionToken — returns temporary credentials for an IAM user."""
    ak = params.get("AccessKeyId", "")
    sk = params.get("SecretAccessKey", "")

    user = _users_by_ak.get(ak)
    if not user:
        return _xml_error("InvalidClientTokenId", "Access key not found")
    if sk and user.get("secret_access_key") != sk:
        return _xml_error("SignatureDoesNotMatch", "Secret access key mismatch")

    creds = _generate_credentials(user["name"], "session")
    creds_elem = _elem("Credentials")
    SubElement(creds_elem, "AccessKeyId").text = creds["AccessKeyId"]
    SubElement(creds_elem, "SecretAccessKey").text = creds["SecretAccessKey"]
    SubElement(creds_elem, "SessionToken").text = creds["SessionToken"]
    SubElement(creds_elem, "Expiration").text = creds["Expiration"]

    xml = _xml_response("GetSessionToken", [creds_elem])
    return (xml, 200, {"Content-Type": "application/xml"})


# Need urllib.parse for form body parsing
import urllib.parse

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
