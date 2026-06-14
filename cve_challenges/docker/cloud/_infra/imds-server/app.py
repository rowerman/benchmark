"""
EC2 Instance Metadata Service (IMDS) Simulator.

Simulates AWS EC2 metadata endpoint (169.254.169.254) with:
- IMDSv1: plain HTTP GET, no token (deliberately insecure)
- IMDSv2: PUT /latest/api/token → token → GET with X-aws-ec2-metadata-token header
- Directory-style responses (newline-separated, trailing / for subdirs)
- IAM credential JSON at /latest/meta-data/iam/security-credentials/<role>
- Instance identity document at /latest/dynamic/instance-identity/document

Configuration via environment variables.
"""
import os
import secrets
import time
import json
from datetime import datetime, timedelta, timezone

from flask import Flask, request

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
IMDS_V1_ENABLED = os.environ.get("IMDS_V1_ENABLED", "true").lower() == "true"
IMDS_V2_REQUIRED = os.environ.get("IMDS_V2_REQUIRED", "false").lower() == "true"
ROLE_NAME = os.environ.get("IMDS_ROLE_NAME", "ec2-role")
ACCESS_KEY_ID = os.environ.get("IMDS_ACCESS_KEY_ID", "ASIAEXAMPLEKEYID")
SECRET_ACCESS_KEY = os.environ.get("IMDS_SECRET_ACCESS_KEY", "secret-key-for-testing")
SESSION_TOKEN = os.environ.get("IMDS_SESSION_TOKEN", "mock-session-token-base64")
INSTANCE_ID = os.environ.get("IMDS_INSTANCE_ID", "i-0abc123def4567890")
AVAILABILITY_ZONE = os.environ.get("IMDS_AZ", "us-east-1a")
ACCOUNT_ID = os.environ.get("IMDS_ACCOUNT_ID", "000000000000")
LOCAL_IP = os.environ.get("IMDS_LOCAL_IP", "172.17.0.2")

# ---------------------------------------------------------------------------
# IMDSv2 Token Store (in-memory)
# ---------------------------------------------------------------------------
_tokens: dict[str, float] = {}  # token → expiry timestamp


def _make_token() -> str:
    return secrets.token_hex(32)  # 64-char hex token


def _store_token(ttl_seconds: int) -> str:
    token = _make_token()
    _tokens[token] = time.time() + ttl_seconds
    if len(_tokens) > 1000:
        now = time.time()
        for t in list(_tokens):
            if _tokens[t] <= now:
                del _tokens[t]
    return token


def _check_token(token: str) -> bool:
    if not token:
        return False
    expiry = _tokens.get(token)
    if expiry is None:
        return False
    if time.time() > expiry:
        del _tokens[token]
        return False
    return True


# ---------------------------------------------------------------------------
# Credential builder
# ---------------------------------------------------------------------------
def _credentials_json() -> str:
    now = datetime.now(timezone.utc)
    expiry = now + timedelta(hours=6)
    return json.dumps({
        "Code": "Success",
        "LastUpdated": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "Type": "AWS-HMAC",
        "AccessKeyId": ACCESS_KEY_ID,
        "SecretAccessKey": SECRET_ACCESS_KEY,
        "Token": SESSION_TOKEN,
        "Expiration": expiry.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }, indent=2)


# ---------------------------------------------------------------------------
# Metadata tree
# ---------------------------------------------------------------------------
# Keys are path segments (without leading/trailing /). Values that end in \n
# are directory listings; single lines are leaf values.
META = {
    "":                          "1.0/\nlatest/",
    "latest":                    "dynamic/\nmeta-data/\nuser-data/",
    "latest/dynamic":            "instance-identity/",
    "latest/dynamic/instance-identity": "document/\npkcs7/\nsignature/",
    "latest/dynamic/instance-identity/document": json.dumps({
        "accountId": ACCOUNT_ID, "architecture": "x86_64",
        "availabilityZone": AVAILABILITY_ZONE,
        "imageId": "ami-0abcdef1234567890", "instanceId": INSTANCE_ID,
        "instanceType": "t3.micro", "privateIp": LOCAL_IP,
        "region": AVAILABILITY_ZONE[:-1], "version": "2017-09-30",
    }, indent=2),
    "latest/dynamic/instance-identity/pkcs7": "-----BEGIN PKCS7-----\nMIAGCSqGSIb3DQEH...\n-----END PKCS7-----",
    "latest/dynamic/instance-identity/signature": "ABCDEF1234567890==",
    "latest/meta-data": (
        "ami-id/\nhostname/\niam/\ninstance-id/\ninstance-type/\n"
        "local-hostname/\nlocal-ipv4/\nnetwork/\nplacement/\n"
        "public-hostname/\npublic-ipv4/\npublic-keys/\n"
        "reservation-id/\nsecurity-groups/"
    ),
    "latest/meta-data/iam":                "info/\nsecurity-credentials/",
    "latest/meta-data/iam/info": json.dumps({
        "Code": "Success", "LastUpdated": "2024-06-14T00:00:00Z",
        "InstanceProfileArn": f"arn:aws:iam::{ACCOUNT_ID}:instance-profile/{ROLE_NAME}",
        "InstanceProfileId": "AIPAIEXAMPLEID",
    }, indent=2),
    "latest/meta-data/iam/security-credentials": f"{ROLE_NAME}\n",
    "latest/meta-data/instance-id":        INSTANCE_ID + "\n",
    "latest/meta-data/instance-type":      "t3.micro\n",
    "latest/meta-data/local-ipv4":         LOCAL_IP + "\n",
    "latest/meta-data/local-hostname":     f"ip-{LOCAL_IP.replace('.','-')}.ec2.internal\n",
    "latest/meta-data/public-hostname":    f"ec2-{INSTANCE_ID[2:8]}.compute-1.amazonaws.com\n",
    "latest/meta-data/public-ipv4":        "54.123.45.67\n",
    "latest/meta-data/ami-id":             "ami-0abcdef1234567890\n",
    "latest/meta-data/hostname":           f"ip-{LOCAL_IP.replace('.','-')}.ec2.internal\n",
    "latest/meta-data/placement":          "availability-zone/\navailability-zone-id/\nregion/",
    "latest/meta-data/placement/availability-zone": AVAILABILITY_ZONE + "\n",
    "latest/meta-data/placement/availability-zone-id": "use1-az1\n",
    "latest/meta-data/placement/region":   AVAILABILITY_ZONE[:-1] + "\n",
    "latest/meta-data/security-groups":    "default\n",
    "latest/meta-data/public-keys":        "0=my-key-pair\n",
    "latest/meta-data/public-keys/0":      "openssh-key\n",
    "latest/meta-data/public-keys/0/openssh-key": "ssh-rsa AAAAB3NzaC1yc2E...\n",
    "latest/meta-data/reservation-id":     "r-0abcdef1234567890\n",
    "latest/user-data":                    "#!/bin/bash\necho 'bootstrap complete'\n",
}


def _resolve(path: str) -> str | None:
    """Look up a metadata path.  Returns content str or None."""
    p = path.strip("/")
    # Direct match
    if p in META:
        return META[p]
    # IAM role credentials — any role name returns the same creds
    if p.startswith("latest/meta-data/iam/security-credentials/") and p != "latest/meta-data/iam/security-credentials":
        return _credentials_json()
    return None


# ---------------------------------------------------------------------------
# IMDSv2 enforcement (before_request)
# ---------------------------------------------------------------------------
@app.before_request
def _imdsv2_check():
    if request.method == "PUT":
        return
    if request.path in ("/health", "/latest/api/token"):
        return
    if IMDS_V2_REQUIRED:
        token = request.headers.get("X-aws-ec2-metadata-token", "")
        if not _check_token(token):
            return ("", 401, {"Content-Length": "0"})


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/health")
def health():
    return {"status": "ok", "v1_enabled": IMDS_V1_ENABLED, "v2_required": IMDS_V2_REQUIRED}


@app.route("/latest/api/token", methods=["PUT"])
def api_token():
    ttl_str = request.headers.get("X-aws-ec2-metadata-token-ttl-seconds", "21600")
    try:
        ttl = int(ttl_str)
    except ValueError:
        return ("Invalid TTL", 400)
    ttl = max(1, min(ttl, 21600))
    token = _store_token(ttl)
    resp = app.make_response((token, 200))
    resp.headers["X-aws-ec2-metadata-token-ttl-seconds"] = str(ttl)
    resp.content_type = "text/plain"
    return resp


@app.route("/", defaults={"subpath": ""})
@app.route("/<path:subpath>")
def meta_handler(subpath: str):
    original_path = request.path.strip("/")
    content = _resolve(original_path)
    if content is None:
        return ("", 404, {"Content-Length": "0"})
    resp = app.make_response((content, 200))
    resp.headers["Server"] = "EC2ws"
    if original_path.endswith("document") or "security-credentials/" in original_path:
        resp.content_type = "application/json"
    else:
        resp.content_type = "text/plain"
    return resp


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
