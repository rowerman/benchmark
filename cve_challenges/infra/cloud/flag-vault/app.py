"""
Flag Vault — 云场景的统一 flag 终点。

flag 只在这里交付：请求必须通过本场景声明的云语义校验（签名、派生凭据、证书、内部令牌、
网络来源），否则一律 403。校验模式与参数来自环境变量，flag 由 start-scenario.sh 经
inject-flags.py 以 root-only 文件写进容器，进程启动时读入内存。

模式：
  sigv4          校验 AWS SigV4 签名（期望的 AK/SK 由 VAULT_CONFIG 给出）
  session-creds  校验三段式临时凭据，并向 IAM 服务反查会话与角色
  jwt            校验 JWT 的 RS256 签名与 iss/aud/sub/自定义声明
  saml           校验 SAML 断言：X509Certificate 匹配 IdP，且 SignatureValue 是
                 对解码后 <saml:Assertion>…</saml:Assertion> 原始字节的 RSA-SHA256 签名
  mtls           校验客户端证书由内部 CA 签发且 CN 命中场景规则
  header-secret  校验指定请求头等于某个只在供应商内部存在的值
  network-source 校验请求来源地址落在受信网段（例如必须经共享 NAT 出口）
"""
import base64
import hashlib
import hmac
import json
import os
import re
import urllib.parse
import urllib.request
from fnmatch import fnmatch

import jwt as pyjwt
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from flask import Flask, request

app = Flask(__name__)

SCENARIO = os.environ.get("VAULT_SCENARIO", "cloud-xx")
MODE = os.environ.get("VAULT_MODE", "header-secret")
FLAG_FILE = os.environ.get("VAULT_FLAG_FILE", "/vault/flag")
FLAG2_FILE = os.environ.get("VAULT_FLAG2_FILE", "/vault/flag2")
IAM_URL = os.environ.get("VAULT_IAM_URL", "http://iam:5000")

try:
    CONFIG = json.loads(os.environ.get("VAULT_CONFIG", "{}"))
except json.JSONDecodeError:
    CONFIG = {}


def load_flag(path: str = FLAG_FILE) -> str:
    """从注入文件读入本轮 flag；文件只在容器内 root-only 可读。"""
    try:
        with open(path, encoding="utf-8") as handle:
            return handle.read().strip()
    except OSError:
        return ""


# 生产路径是注入文件；文件缺失时允许用环境变量（只用于组件自测）。
FLAG = load_flag() or os.environ.get("VAULT_FLAG", "").strip()
# 双 flag 场景（如 cloud-13/17）的第二枚 flag，走同一套校验
FLAG2 = load_flag(FLAG2_FILE)

# ── SigV4 ─────────────────────────────────────────────────────────────────


def _uri_encode(value: str, with_slash: bool = False) -> str:
    safe = "-_.~/" if with_slash else "-_.~"
    return urllib.parse.quote(value, safe=safe)


def verify_sigv4() -> bool:
    header = request.headers.get("Authorization", "")
    if not header.startswith("AWS4-HMAC-SHA256 "):
        return False
    parts = dict(
        item.strip().split("=", 1) for item in header[len("AWS4-HMAC-SHA256 "):].split(",") if "=" in item
    )
    credential = parts.get("Credential", "")
    signed_headers = parts.get("SignedHeaders", "")
    signature = parts.get("Signature", "")
    pieces = credential.split("/")
    if len(pieces) != 5 or not signed_headers or not signature:
        return False
    access_key, date_stamp, region, service, terminator = pieces
    expected_key = CONFIG.get("access_key", "")
    expected_secret = CONFIG.get("secret_key", "")
    if not expected_key or access_key != expected_key:
        return False

    amz_date = request.headers.get("X-Amz-Date", "")
    if not amz_date:
        return False

    pairs = urllib.parse.parse_qsl(request.query_string.decode(), keep_blank_values=True)
    canonical_query = "&".join(
        f"{_uri_encode(k)}={_uri_encode(v)}" for k, v in sorted(pairs, key=lambda kv: (kv[0], kv[1]))
    )
    header_names = signed_headers.split(";")
    canonical_headers = ""
    for name in header_names:
        value = request.headers.get(name)
        if value is None:
            return False
        canonical_headers += f"{name}:{' '.join(value.split())}\n"
    payload = request.get_data() or b""
    payload_hash = request.headers.get("X-Amz-Content-Sha256") or hashlib.sha256(payload).hexdigest()
    canonical_request = "\n".join([
        request.method,
        _uri_encode(request.path, with_slash=True),
        canonical_query,
        canonical_headers,
        signed_headers,
        payload_hash,
    ])
    scope = f"{date_stamp}/{region}/{service}/{terminator}"
    string_to_sign = "\n".join([
        "AWS4-HMAC-SHA256",
        amz_date,
        scope,
        hashlib.sha256(canonical_request.encode()).hexdigest(),
    ])
    key = ("AWS4" + expected_secret).encode()
    for item in (date_stamp, region, service, terminator):
        key = hmac.new(key, item.encode(), hashlib.sha256).digest()
    expected = hmac.new(key, string_to_sign.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


# ── 派生凭据 ───────────────────────────────────────────────────────────────


def verify_session_creds() -> bool:
    body = request.get_json(silent=True) or {}
    access_key = body.get("access_key") or request.headers.get("X-Access-Key-Id", "")
    secret_key = body.get("secret_key") or request.headers.get("X-Secret-Access-Key", "")
    session_token = body.get("session_token") or request.headers.get("X-Session-Token", "")
    if not (access_key and secret_key and session_token):
        return False
    payload = json.dumps({
        "access_key": access_key, "secret_key": secret_key, "session_token": session_token,
    }).encode()
    req = urllib.request.Request(
        f"{IAM_URL.rstrip('/')}/validate", data=payload,
        headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            result = json.loads(response.read().decode())
    except Exception:
        return False
    allowed = CONFIG.get("roles") or []
    if not result.get("valid"):
        return False
    return not allowed or result.get("role") in allowed


# ── JWT ───────────────────────────────────────────────────────────────────

_public_key = None


def _load_public_key():
    global _public_key
    if _public_key is not None:
        return _public_key
    pem_file = CONFIG.get("public_key_file")
    if pem_file and os.path.exists(pem_file):
        with open(pem_file, "rb") as handle:
            _public_key = serialization.load_pem_public_key(handle.read())
        return _public_key
    jwks_url = CONFIG.get("jwks_url")
    if jwks_url:
        try:
            with urllib.request.urlopen(jwks_url, timeout=5) as response:
                jwks = json.loads(response.read().decode())
            for item in jwks.get("keys", []):
                if item.get("kty") == "RSA":
                    modulus = int.from_bytes(
                        base64.urlsafe_b64decode(item["n"] + "=="), "big")
                    exponent = int.from_bytes(
                        base64.urlsafe_b64decode(item["e"] + "=="), "big")
                    _public_key = rsa.RSAPublicNumbers(exponent, modulus).public_key()
                    return _public_key
        except Exception:
            return None
    return None


def _claims_match(claims: dict) -> bool:
    """逐条比对期望声明；值支持 glob（如 repo:demo-org/demo-repo:*）。"""
    for name, expected in (CONFIG.get("claims") or {}).items():
        value = claims.get(name)
        if value is None:
            return False
        if not fnmatch(str(value), str(expected)):
            return False
    return True


def verify_jwt() -> bool:
    header = request.headers.get("Authorization", "")
    token = header[7:].strip() if header.lower().startswith("bearer ") else ""
    if not token:
        return False
    issuer = CONFIG.get("issuer") or None
    key = _load_public_key()
    if key is not None:
        try:
            claims = pyjwt.decode(token, key, algorithms=["RS256"],
                                  options={"verify_aud": False}, issuer=issuer)
        except Exception:
            return False
    else:
        # 共享密钥签发方（平台内部令牌服务）走 HS256
        secret = CONFIG.get("hmac_secret")
        if not secret:
            return False
        try:
            claims = pyjwt.decode(token, secret, algorithms=["HS256"],
                                  options={"verify_aud": False}, issuer=issuer)
        except Exception:
            return False
    audience = CONFIG.get("audience")
    if audience and audience not in (claims.get("aud") or []):
        return False
    return _claims_match(claims)


# ── SAML ──────────────────────────────────────────────────────────────────


def verify_saml() -> bool:
    body = request.get_json(silent=True) or {}
    encoded = body.get("SAMLResponse") or request.form.get("SAMLResponse", "")
    if not encoded:
        return False
    try:
        raw = base64.b64decode(encoded).decode("utf-8", errors="replace")
    except Exception:
        return False
    start = raw.find("<saml:Assertion")
    if start < 0:
        start = raw.find("<saml2:Assertion")
    if start < 0:
        return False
    marker = "</saml:Assertion>" if raw[start:].find("</saml:Assertion>") >= 0 else "</saml2:Assertion>"
    end = raw.find(marker, start)
    if end < 0:
        return False
    assertion = raw[start:end + len(marker)]
    values = re.findall(r"<ds:SignatureValue>([^<]+)</ds:SignatureValue>", assertion)
    certs = re.findall(r"<ds:X509Certificate>([^<]+)</ds:X509Certificate>", assertion)
    name_ids = re.findall(r"<saml:NameID[^>]*>([^<]+)</saml:NameID>", assertion) or \
        re.findall(r"<saml2:NameID[^>]*>([^<]+)</saml2:NameID>", assertion)
    if not values or not certs or not name_ids:
        return False
    expected_cert = CONFIG.get("idp_cert", "").replace("\n", "").strip()
    if expected_cert and certs[0].strip() != expected_cert:
        return False
    expected_name = CONFIG.get("name_id")
    if expected_name and name_ids[0].strip() != expected_name:
        return False
    # 签名对象：断言去掉 <ds:Signature>…</ds:Signature> 之后的那段字节（信封签名的模拟契约）
    signed_payload = re.sub(r"<ds:Signature>.*?</ds:Signature>", "", assertion, flags=re.S)
    try:
        cert = x509.load_der_x509_certificate(base64.b64decode(certs[0]))
        cert.public_key().verify(
            base64.b64decode(values[0]), signed_payload.encode("utf-8"),
            padding.PKCS1v15(), hashes.SHA256())
    except Exception:
        return False
    return True


# ── 客户端证书 ─────────────────────────────────────────────────────────────

_ca_cert = None


def _load_ca():
    global _ca_cert
    if _ca_cert is not None:
        return _ca_cert
    url = CONFIG.get("ca_url")
    if not url:
        return None
    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            payload = json.loads(response.read().decode())
        _ca_cert = x509.load_pem_x509_certificate(base64.b64decode(payload["ca"]))
    except Exception:
        return None
    return _ca_cert


def verify_mtls() -> bool:
    pem = request.headers.get("X-Client-Cert", "").strip()
    if not pem:
        return False
    if not pem.startswith("-----BEGIN"):
        # 证书走 HTTP 头传递，用 base64 包一层（头里不能出现换行）
        try:
            pem = base64.b64decode(pem).decode()
        except Exception:
            return False
    ca_cert = _load_ca()
    if ca_cert is None:
        return False
    try:
        cert = x509.load_pem_x509_certificate(pem.encode())
        ca_cert.public_key().verify(
            cert.signature, cert.tbs_certificate_bytes,
            padding.PKCS1v15(), cert.signature_hash_algorithm)
    except Exception:
        return False
    common_name = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
    if not common_name:
        return False
    rule = CONFIG.get("cn_rule", ".*")
    return bool(re.match(rule, common_name[0].value))


# ── 通用头令牌 / 网络来源 ───────────────────────────────────────────────────


def verify_header_secret() -> bool:
    name = CONFIG.get("header", "X-Internal-Token")
    presented = request.headers.get(name, "")
    for expected in CONFIG.get("values", []):
        if presented and hmac.compare_digest(presented, expected):
            return True
    return False


def verify_network_source() -> bool:
    forwarded = request.headers.get("X-Forwarded-For", "")
    peer = forwarded.split(",")[0].strip() if forwarded else (request.remote_addr or "")
    for cidr in CONFIG.get("cidrs", []):
        if "/" in cidr:
            network, bits = cidr.split("/")
            try:
                import ipaddress
                if ipaddress.ip_address(peer) in ipaddress.ip_network(cidr, strict=False):
                    return True
            except ValueError:
                continue
        elif peer == cidr:
            return True
    return False


VERIFIERS = {
    "sigv4": verify_sigv4,
    "session-creds": verify_session_creds,
    "jwt": verify_jwt,
    "saml": verify_saml,
    "mtls": verify_mtls,
    "header-secret": verify_header_secret,
    "network-source": verify_network_source,
}


@app.route("/health")
def health():
    return {"status": "ok", "scenario": SCENARIO, "mode": MODE, "flag_loaded": bool(FLAG)}


@app.route("/requirements")
def requirements():
    """公布本终点要求的校验方式（不含任何秘密），供侦察阶段发现。"""
    return {"scenario": SCENARIO, "mode": MODE,
            "hint": CONFIG.get("hint", ""), "verifier": list(VERIFIERS)}


@app.route("/flag", methods=["GET", "POST"])
def flag():
    if not FLAG:
        return "flag not loaded", 500
    verifier = VERIFIERS.get(MODE)
    if verifier is None:
        return "verifier unavailable", 500
    if not verifier():
        return "access denied", 403
    return FLAG, 200, {"Content-Type": "text/plain; charset=utf-8"}


@app.route("/flag2", methods=["GET", "POST"])
def flag2():
    """双 flag 场景的第二枚 flag；校验方式与 /flag 完全一致。"""
    if not FLAG2:
        return "flag not loaded", 500
    verifier = VERIFIERS.get(MODE)
    if verifier is None:
        return "verifier unavailable", 500
    if not verifier():
        return "access denied", 403
    return FLAG2, 200, {"Content-Type": "text/plain; charset=utf-8"}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
