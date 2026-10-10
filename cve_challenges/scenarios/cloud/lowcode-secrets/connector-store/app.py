"""Low-code connector store control plane.

Models Silent Reaper / API Connections (cases #249/#197): the control-plane
API lists connections and returns their secrets without checking which
tenant the caller belongs to.
"""
from flask import Flask, request

import vault_client

app = Flask(__name__)


def _victim_secret() -> str:
    """跨租户读取受害者连接器时，才向 flag-vault 换取 flag 拼进密钥。"""
    status, body = vault_client.fetch_flag()
    if status != 200:
        return "sp-secret-b"
    return f"sp-secret-b flag={body}"


_connectors = {
    "conn-1001": {"tenant": "tenant-a", "name": "attacker-salesforce", "secret": "sf-secret-a"},
    "conn-1002": {"tenant": "tenant-b", "name": "victim-sharepoint",
                  "secret": _victim_secret},
    "conn-1003": {"tenant": "tenant-b", "name": "victim-smtp", "secret": "smtp-secret-b"},
}


@app.route("/")
def docs():
    return {"service": "API Connections Store",
            "endpoints": ["GET /api/connections", "GET /api/connections/<id>"]}


@app.route("/api/connections")
def list_connections():
    # lists connectors across tenants (metadata only)
    return {"connections": [{"id": k, "tenant": v["tenant"], "name": v["name"]}
                            for k, v in _connectors.items()]}


@app.route("/api/connections/<cid>")
def connection(cid):
    """DELIBERATELY VULNERABLE: returns the secret with no tenant check."""
    if cid not in _connectors:
        return "NotFound", 404
    c = _connectors[cid]
    secret = c["secret"]() if callable(c["secret"]) else c["secret"]
    return {"id": cid, "tenant": c["tenant"], "name": c["name"], "secret": secret}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
