"""Shared managed NAT egress.

Models provider-managed egress shared by many tenants: requests leaving
through this gateway originate from a trusted provider address range, which
victim firewalls that key on source-IP service ranges accept (case #259).
"""
import os
import urllib.request

from flask import Flask, request

app = Flask(__name__)


@app.route("/health")
def health():
    return {"status": "ok"}


@app.route("/egress", methods=["POST"])
def egress():
    """Forward a request to an arbitrary target from the trusted egress IP."""
    body = request.get_json(silent=True) or {}
    url = body.get("url", "")
    if not url:
        return {"error": "missing url"}, 400
    if not url.startswith("http://") and not url.startswith("https://"):
        return {"error": "invalid url"}, 400
    try:
        req = urllib.request.Request(
            url,
            data=body.get("data", "").encode() if body.get("data") else None,
            method=body.get("method", "GET"),
        )
        r = urllib.request.urlopen(req, timeout=8)
        return {"status": r.status, "body": r.read().decode(errors="replace")}
    except urllib.error.HTTPError as e:
        return {"status": e.code, "body": e.read().decode(errors="replace")}
    except Exception as e:
        return {"error": str(e)}, 502


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
