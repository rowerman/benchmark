"""Victim API protected by a source-IP allowlist keyed to a provider
service range (Azure service tags lineage, #259)."""
import ipaddress
import os
import requests

from flask import Flask, request

import vault_client

app = Flask(__name__)
NAT_URL = os.environ.get("NAT_URL", "")
TRUSTED = [ipaddress.ip_network("168.63.0.10/32")]


@app.route("/")
def rules():
    return {"firewall": "source-IP allowlist", "trusted_ranges": [str(n) for n in TRUSTED],
            "note": "requests from Azure service ranges are treated as trusted"}


@app.route("/flag")
def flag():
    src = request.remote_addr
    if any(ipaddress.ip_address(src) in n for n in TRUSTED):
        # 放行后 flag 由 flag-vault 按本服务地址交付，容器里不留明文
        status, body = vault_client.fetch_flag()
        return {"source": src, "trusted": True, "flag": body if status == 200 else ""}
    return {"source": src, "trusted": False, "error": "source IP not in trusted service range"}, 403


@app.route("/egress", methods=["POST"])
def egress():
    if not NAT_URL:
        return {"error": "shared egress unavailable"}, 503
    response = requests.post(f"{NAT_URL}/egress", json={"url": "http://victim-api:5000/flag"}, timeout=8)
    return response.text, response.status_code, {"Content-Type": response.headers.get("Content-Type", "text/plain")}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
