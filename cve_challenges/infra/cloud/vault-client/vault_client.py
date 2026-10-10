"""云场景 flag broker 客户端。

终端服务不再自己持有 flag，而是向 flag-vault 出示"本场景要求的那份云语义凭据"
换取 flag。凭据由终端服务按场景语义构造（或直接转交调用方出示的那份）。

用法示例（凭据构造 + 取 flag）：

    import vault_client
    status, body = vault_client.fetch_flag(vault_client.sigv4_headers(ak, sk))
    status, body = vault_client.fetch_flag(vault_client.session_creds(ak, sk, token))
    status, body = vault_client.fetch_flag(vault_client.bearer(token))
    status, body = vault_client.fetch_flag(vault_client.saml(assertion_b64))
    status, body = vault_client.fetch_flag(vault_client.header_secret("X-Internal-Token", token))
    status, body = vault_client.fetch_flag()   # network-source：靠来源地址放行
"""
from __future__ import annotations

import datetime
import hashlib
import hmac
import json
import os
import urllib.error
import urllib.parse
import urllib.request

VAULT_URL = os.environ.get("VAULT_URL", "http://flag-vault:5000")


def sigv4_headers(access_key: str, secret_key: str, *, region: str = "us-east-1",
                  service: str = "s3", path: str = "/flag") -> dict[str, str]:
    """按 AWS SigV4 对 path 签名，返回可直接附到请求上的头。"""
    host = urllib.parse.urlparse(VAULT_URL).netloc
    terminator = "aws4_request"
    now = datetime.datetime.now(datetime.timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")
    signed_headers = "host;x-amz-date"
    payload_hash = hashlib.sha256(b"").hexdigest()
    canonical_request = "\n".join([
        "GET", urllib.parse.quote(path, safe="-_.~/"), "",
        f"host:{host}\nx-amz-date:{amz_date}\n", signed_headers, payload_hash,
    ])
    scope = f"{date_stamp}/{region}/{service}/{terminator}"
    string_to_sign = "\n".join([
        "AWS4-HMAC-SHA256", amz_date, scope,
        hashlib.sha256(canonical_request.encode()).hexdigest(),
    ])
    key = ("AWS4" + secret_key).encode()
    for item in (date_stamp, region, service, terminator):
        key = hmac.new(key, item.encode(), hashlib.sha256).digest()
    signature = hmac.new(key, string_to_sign.encode(), hashlib.sha256).hexdigest()
    return {
        "Host": host,
        "X-Amz-Date": amz_date,
        "X-Amz-Content-Sha256": payload_hash,
        "Authorization": (
            f"AWS4-HMAC-SHA256 Credential={access_key}/{scope}, "
            f"SignedHeaders={signed_headers}, Signature={signature}"),
    }


def session_creds(access_key: str, secret_key: str, session_token: str) -> dict[str, str]:
    """三段式临时凭据，以 JSON 体提交（对应 flag-vault 的 session-creds 模式）。"""
    return {"_body": json.dumps({
        "access_key": access_key, "secret_key": secret_key, "session_token": session_token,
    })}


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def saml(assertion_b64: str) -> dict[str, str]:
    return {"_body": json.dumps({"SAMLResponse": assertion_b64})}


def header_secret(name: str, value: str) -> dict[str, str]:
    return {name: value}


def fetch_flag(proof: dict[str, str] | None = None, *, path: str = "/flag",
               timeout: float = 5) -> tuple[int, str]:
    """把凭据交给 flag-vault，返回 (状态码, 响应体)；校验不过时为 403。"""
    proof = dict(proof or {})
    body = proof.pop("_body", None)
    request = urllib.request.Request(f"{VAULT_URL}{path}",
                                     data=body.encode() if body else None,
                                     headers=proof, method="POST" if body else "GET")
    if body:
        request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, response.read().decode(errors="replace")
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode(errors="replace")
    except OSError as error:
        return 502, f"flag-vault unreachable: {error}"
