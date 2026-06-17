"""API Gateway — reverse proxy with header smuggling vulnerability."""
import os, urllib.request
from flask import Flask, request

app = Flask(__name__)
BACKEND = os.environ.get("BACKEND_URL", "http://backend:5000")
ADMIN = os.environ.get("ADMIN_URL", "http://admin:5000")

@app.route("/health")
def health(): return {"status": "ok"}

@app.route("/robots.txt")
def robots():
    """Hints at hidden admin area without revealing the exact path."""
    return """User-agent: *
Disallow: /admin
# Internal admin panel — not for public access""", 200, {"Content-Type": "text/plain"}

@app.route("/api/<path:subpath>")
def api_proxy(subpath):
    try:
        r = urllib.request.urlopen(f"{BACKEND}/{subpath}", timeout=5)
        return r.read().decode(), r.status
    except Exception as e:
        return f"Backend error: {e}", 502

@app.route("/")
def home():
    return """API Gateway v2.0 — Documentation

Public Endpoints:
  GET /api/data       — Public API data

For internal admin access, consult your network administrator."""

@app.route("/admin")
def admin():
    # IP whitelist check — bypassable via X-Forwarded-For header smuggling
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    if client_ip.startswith("10.") or client_ip.startswith("172.") or client_ip == "127.0.0.1":
        try:
            r = urllib.request.urlopen(f"{ADMIN}/secrets", timeout=5)
            return r.read().decode(), r.status
        except: return "Admin unreachable", 502
    return f"Access denied — {client_ip} is not an internal IP. Only internal IPs (10.x, 172.x, 127.0.0.1) are allowed.", 403

if __name__ == "__main__": app.run(host="0.0.0.0", port=5000)
