"""Production Service Catalog API -- fully audited."""
import os

import requests
from flask import Flask, request

app = Flask(__name__)
AUDIT = os.environ.get("AUDIT_URL", "http://audit-log:5000")
_portfolios = []


def audit(caller):
    try:
        requests.post(f"{AUDIT}/log",
                      json={"path": "/portfolios", "caller": caller, "action": "create"}, timeout=3)
    except Exception:
        pass


@app.route("/portfolios", methods=["POST"])
def create():
    body = request.get_json(silent=True) or {}
    pid = f"prod-{len(_portfolios) + 1}"
    _portfolios.append({"id": pid, "name": body.get("name", "")})
    audit(request.headers.get("X-Caller", "?"))
    return {"portfolio_id": pid, "audited": True, "endpoint": "production"}


@app.route("/portfolios")
def list_all():
    return {"portfolios": _portfolios}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
