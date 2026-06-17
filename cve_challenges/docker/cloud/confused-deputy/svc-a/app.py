"""Service A — internal service with managed identity proxy."""
import os, urllib.request
from flask import Flask, request

app = Flask(__name__)
MI_TOKEN = "mi-token-svc-a-identity"

@app.route("/health")
def health(): return {"status": "ok"}

@app.route("/")
def home():
    return {
        "service": "svc-a",
        "version": "1.2.0",
        "endpoints": ["/health", "/data", "/debug"],
        "managed_identity": "enabled"
    }

@app.route("/debug")
def debug():
    """Debug page — shows internal routing table (hints at /proxy)."""
    return {
        "routes": {
            "/health": "GET — health check",
            "/": "GET — service info",
            "/data": "GET — internal data",
            "/proxy": "GET — forward request to internal service (requires internal caller)",
            "/debug": "GET — this page"
        },
        "auth_header": f"Bearer {MI_TOKEN[:20]}..."
    }

@app.route("/proxy")
def proxy():
    """Forward requests to internal services using managed identity."""
    target = request.args.get("to", "")
    if not target:
        return {"error": "missing target parameter"}, 400
    try:
        req = urllib.request.Request(f"http://{target}/data",
            headers={"Authorization": f"Bearer {MI_TOKEN}"})
        r = urllib.request.urlopen(req, timeout=5)
        return r.read().decode(), r.status, {"Content-Type": "application/json"}
    except Exception as e:
        return {"error": str(e)}, 502

if __name__ == "__main__": app.run(host="0.0.0.0", port=5000)
