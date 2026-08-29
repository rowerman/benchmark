"""S3 Target — cross-account protected resource."""
import os
import json
import urllib.request
from flask import Flask, request
app = Flask(__name__)
FLAG = os.environ.get("FLAG", "flag{cloud-08-step2-cross-account}")
IAM_URL = os.environ.get("IAM_URL", "http://iam:5000")
@app.route("/health")
def health(): return {"status":"ok"}
@app.route("/flag.txt")
def flag():
    payload = json.dumps({
            "access_key": request.headers.get("X-Access-Key-Id", ""),
            "secret_key": request.headers.get("X-Secret-Access-Key", ""),
            "session_token": request.headers.get("X-Session-Token", ""),
        }).encode()
    req = urllib.request.Request(
        f"{IAM_URL}/validate",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            validation = json.loads(resp.read().decode())
    except Exception:
        return "AccessDenied: valid assumed-role credentials required", 403
    permissions = validation.get("permissions", [])
    if "s3:GetObject" not in permissions and "s3:*" not in permissions:
        return "AccessDenied: role lacks s3:GetObject", 403
    return FLAG
if __name__ == "__main__": app.run(host="0.0.0.0", port=5000)
