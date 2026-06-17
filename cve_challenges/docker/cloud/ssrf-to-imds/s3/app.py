"""
S3-Internal Object Storage Simulator.

Simulates an internal S3-compatible object store that requires
IAM credentials (AccessKeyId + SecretAccessKey) for access.

The credentials are those returned by the IMDS service —
an attacker who steals IMDS credentials can access the control-plane flag.
"""
import os
from flask import Flask, request

app = Flask(__name__)

# Valid credentials — must match what IMDS returns
VALID_AK = os.environ.get("S3_ACCESS_KEY", "AKIACLOUD01EXAMPLE")
VALID_SK = os.environ.get("S3_SECRET_KEY", "cloud01-imds-secret-key")
FLAG = os.environ.get("FLAG", "flag{cloud-01-step2-imds}")

# Store objects in memory
_objects = {
    "flag.txt": FLAG,
    "readme.txt": "This storage requires valid IAM credentials for access.",
}


def _check_auth() -> bool:
    """Validate IAM credentials from request headers."""
    ak = request.headers.get("X-Access-Key-Id", "")
    sk = request.headers.get("X-Secret-Access-Key", "")
    return ak == VALID_AK and sk == VALID_SK


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
    if filepath not in _objects:
        return "NotFound", 404
    return _objects[filepath], 200, {"Content-Type": "text/plain"}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
