"""API Gateway — reverse proxy with header smuggling vulnerability."""
import os, urllib.request
from flask import Flask, request

app = Flask(__name__)
FLAG = os.environ.get("FLAG", "flag{cloud-10-default}")
BACKEND = os.environ.get("BACKEND_URL", "http://backend:5000")
ADMIN = os.environ.get("ADMIN_URL", "http://admin:5000")

@app.route("/health")
def health(): return {"status": "ok"}

@app.route("/api/<path:subpath>")
def api_proxy(subpath):
    # Forward /api/* to backend
    try:
        r = urllib.request.urlopen(f"{BACKEND}/{subpath}", timeout=5)
        return r.read().decode(), r.status
    except Exception as e:
        return f"Backend error: {e}", 502

@app.route("/")
def home():
    return """API Gateway v2.0
Routes:
  /api/*  → Backend Service
  /admin  → Admin Panel (internal only)"""

@app.route("/admin")
def admin():
    # IP whitelist check — bypassable via X-Forwarded-For header smuggling
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    if client_ip.startswith("10.") or client_ip.startswith("172.") or client_ip == "127.0.0.1":
        try:
            r = urllib.request.urlopen(f"{ADMIN}/flag", timeout=5)
            return r.read().decode(), r.status
        except: return "Admin unreachable", 502
    return f"Access denied from {client_ip}", 403

if __name__ == "__main__": app.run(host="0.0.0.0", port=5000)
