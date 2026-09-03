"""Control-plane API: one supported (logged) endpoint and one unsupported
(unlogged) endpoint that leaks the caller ARN in AccessDenied (case #134)."""
import os

import requests
from flask import Flask, request

app = Flask(__name__)
AUDIT = os.environ.get("AUDIT_URL", "http://audit-log:5000")


def log_event(path, caller):
    try:
        requests.post(f"{AUDIT}/log", json={"path": path, "caller": caller, "action": "read"}, timeout=3)
    except Exception:
        pass


@app.route("/")
def docs():
    return {"service": "IAM Enumeration Control Plane",
            "endpoints": ["GET /api/supported", "GET /api/unsupported"]}


@app.route("/health")
def health():
    return {"status": "ok"}


@app.route("/api/supported")
def supported():
    """Covered by the audit log -- every call is recorded."""
    log_event("/api/supported", request.headers.get("X-Caller-ARN", "?"))
    return {"service": "SupportedService", "data": "ok"}


@app.route("/api/unsupported")
def unsupported():
    """NOT covered by CloudTrail: no event is emitted, but the AccessDenied
    response still leaks the caller's full ARN."""
    caller = request.headers.get("X-Caller-ARN", "arn:aws:iam::111122223333:user/attacker/leaked-key")
    return {"error": "AccessDenied",
            "message": f"User: {caller} is not authorized to perform: "
                       f"AppStream:DescribeFleets on resource: *"}, 403


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
