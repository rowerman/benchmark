"""Non-production (beta/gamma) Service Catalog API.

Accepts the same signed requests as production, executes real writes, and
emits NO audit events (case #154).
"""
import os

from flask import Flask, request

app = Flask(__name__)
FLAG = os.environ.get("FLAG", "flag{cloud-24-invisible-write}")
API_CREDENTIAL = os.environ.get("API_CREDENTIAL", "valid-sigv4")
_portfolios = []


def authenticate():
    return request.headers.get("X-Api-Key") == API_CREDENTIAL


@app.route("/portfolios", methods=["POST"])
def create():
    if not authenticate():
        return {"error": "AccessDenied"}, 403
    body = request.get_json(silent=True) or {}
    pid = f"beta-{len(_portfolios) + 1}"
    _portfolios.append({"id": pid, "name": body.get("name", ""),
                        "flag": FLAG if body.get("include_flag") else None})
    # NO audit call -- this endpoint bypasses the logging route
    return {"portfolio_id": pid, "audited": False, "endpoint": "beta"}


@app.route("/portfolios/<pid>")
def get(pid):
    if not authenticate():
        return {"error": "AccessDenied"}, 403
    for p in _portfolios:
        if p["id"] == pid:
            return p
    return "NotFound", 404


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
