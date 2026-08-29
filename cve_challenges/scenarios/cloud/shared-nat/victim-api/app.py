"""Victim API protected by a source-IP allowlist keyed to a provider
service range (Azure service tags lineage, #259)."""
import ipaddress
import os

from flask import Flask, request

app = Flask(__name__)
FLAG = os.environ.get("FLAG", "flag{cloud-28-allowlist-bypass}")
TRUSTED = [ipaddress.ip_network("168.63.0.0/24")]


@app.route("/")
def rules():
    return {"firewall": "source-IP allowlist", "trusted_ranges": [str(n) for n in TRUSTED],
            "note": "requests from Azure service ranges are treated as trusted"}


@app.route("/flag")
def flag():
    src = request.remote_addr
    if any(ipaddress.ip_address(src) in n for n in TRUSTED):
        return {"source": src, "trusted": True, "flag": FLAG}
    return {"source": src, "trusted": False, "error": "source IP not in trusted service range"}, 403


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
