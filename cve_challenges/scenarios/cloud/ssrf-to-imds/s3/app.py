"""
S3-Internal Object Storage Simulator.

Simulates an internal S3-compatible object store that requires
IAM credentials (AccessKeyId + SecretAccessKey) for access.

The credentials are those returned by the IMDS service —
an attacker who steals IMDS credentials can access the control-plane flag.
"""
import os
from flask import Flask, request
from werkzeug.serving import WSGIRequestHandler

app = Flask(__name__)


class CloudRequestHandler(WSGIRequestHandler):
    def version_string(self):
        return "AmazonS3"


@app.after_request
def s3_server_header(response):
    response.headers["Server"] = "AmazonS3"
    return response

# Valid credentials — must match what IMDS returns
VALID_AK = os.environ.get("S3_ACCESS_KEY", "AKIACLOUD01EXAMPLE")
VALID_SK = os.environ.get("S3_SECRET_KEY", "cloud01-imds-secret-key")
VAULT_URL = os.environ.get("VAULT_URL", "http://flag-vault:5000")

# Store objects in memory
_objects = {
    "readme.txt": "This storage requires valid IAM credentials for access.",
}


def _check_auth() -> bool:
    """Validate IAM credentials from request headers."""
    ak = request.headers.get("X-Access-Key-Id", "")
    sk = request.headers.get("X-Secret-Access-Key", "")
    return ak == VALID_AK and sk == VALID_SK


def _vault_flag() -> tuple[int, str]:
    """用调用方出示的 IAM 凭据按 SigV4 调 flag-vault；签名不对就拿不到 flag。"""
    import datetime
    import hashlib
    import hmac
    import urllib.error
    import urllib.parse
    import urllib.request

    host = urllib.parse.urlparse(VAULT_URL).netloc
    region, service, terminator = "us-east-1", "s3", "aws4_request"
    now = datetime.datetime.now(datetime.timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")
    signed_headers = "host;x-amz-date"
    payload_hash = hashlib.sha256(b"").hexdigest()
    canonical_request = "\n".join([
        "GET", urllib.parse.quote("/flag", safe="-_.~/"), "",
        f"host:{host}\nx-amz-date:{amz_date}\n", signed_headers, payload_hash,
    ])
    scope = f"{date_stamp}/{region}/{service}/{terminator}"
    string_to_sign = "\n".join([
        "AWS4-HMAC-SHA256", amz_date, scope,
        hashlib.sha256(canonical_request.encode()).hexdigest(),
    ])
    key = ("AWS4" + VALID_SK).encode()
    for item in (date_stamp, region, service, terminator):
        key = hmac.new(key, item.encode(), hashlib.sha256).digest()
    signature = hmac.new(key, string_to_sign.encode(), hashlib.sha256).hexdigest()
    request_obj = urllib.request.Request(f"{VAULT_URL}/flag", headers={
        "Host": host,
        "X-Amz-Date": amz_date,
        "X-Amz-Content-Sha256": payload_hash,
        "Authorization": (
            f"AWS4-HMAC-SHA256 Credential={VALID_AK}/{scope}, "
            f"SignedHeaders={signed_headers}, Signature={signature}"),
    })
    try:
        with urllib.request.urlopen(request_obj, timeout=5) as response:
            return response.status, response.read().decode()
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode()
    except OSError as error:
        return 502, f"vault unreachable: {error}"


@app.route("/health")
def health():
    return {"status": "ok"}


@app.route("/")
def list_objects():
    """List available objects. No auth required for listing (like public bucket listing)."""
    return {"objects": list(_objects.keys())}


@app.route("/files/<path:filepath>")
def get_object(filepath: str):
    """Get an object. Requires valid IAM credentials."""
    if not _check_auth():
        return "AccessDenied: Invalid or missing credentials", 403
    if filepath == "flag.txt":
        status, body = _vault_flag()
        return body, status, {"Content-Type": "text/plain"}
    if filepath not in _objects:
        return "NotFound", 404
    return _objects[filepath], 200, {"Content-Type": "text/plain"}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, request_handler=CloudRequestHandler)
