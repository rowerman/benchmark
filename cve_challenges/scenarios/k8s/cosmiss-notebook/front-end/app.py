"""Multi-tenant notebook front-end with a broken tenant binding layer."""
import os
import urllib.parse
import urllib.request

import jwt
from flask import Flask, request

app = Flask(__name__)
SIGNING_SECRET = os.environ.get("SIGNING_SECRET", "cosmiss-front-secret-2026-shared-key")

NOTEBOOKS = {
    "fwd-7f3a91b2-cb4e-4b6e-9a0f-000000000001": {"name": "nb-a", "url": "http://nb-a:5000", "owner": "tenant-a"},
    "fwd-8c1d4e5f-6a2b-4c3d-8e9f-000000000002": {"name": "nb-b", "url": "http://nb-b:5000", "owner": "tenant-b"},
}

HOME = """<h1>Managed Notebooks</h1>
<p>Welcome to the provider's notebook service. Open a notebook you own via its
forwarding link below.</p>
<ul>
  <li><a href="/notebook/fwd-7f3a91b2-cb4e-4b6e-9a0f-000000000001">My notebook (nb-a)</a></li>
  <li><a href="/notebook/fwd-8c1d4e5f-6a2b-4c3d-8e9f-000000000002">Shared notebook from team research</a></li>
</ul>
<p><small>The forwarding links are shared inside the company wiki; they are not
intended to be public.</small></p>"""


@app.route("/")
def home():
    return HOME


@app.route("/auth/token")
def token():
    return {"token": jwt.encode({"tenant": "tenant-a", "sub": "alice"}, SIGNING_SECRET, algorithm="HS256")}


def caller_tenant():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    try:
        return jwt.decode(auth[7:], SIGNING_SECRET, algorithms=["HS256"]).get("tenant")
    except jwt.PyJWTError:
        return None


@app.route("/notebook/<fwd_id>")
def notebook_info(fwd_id):
    nb = NOTEBOOKS.get(fwd_id)
    if not nb:
        return "Not found", 404
    if caller_tenant() is None:
        return {"error": "Unauthorized"}, 401
    return {"notebook": nb["name"], "owner": nb["owner"], "endpoint": f"/notebook/{fwd_id}/exec"}


@app.route("/notebook/<fwd_id>/exec")
def exec_code(fwd_id):
    nb = NOTEBOOKS.get(fwd_id)
    if not nb:
        return "Not found", 404
    if caller_tenant() is None:
        return {"error": "Unauthorized"}, 401
    # DELIBERATELY VULNERABLE: the signed tenant is not bound to nb['owner'].
    code = request.args.get("code", "")
    try:
        url = f"{nb['url']}/exec?code={urllib.parse.quote(code)}"
        r = urllib.request.urlopen(url, timeout=8)
        return r.read().decode(errors="replace")
    except Exception as e:
        return f"Notebook error: {e}", 502


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
