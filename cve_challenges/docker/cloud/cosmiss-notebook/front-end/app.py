"""Multi-tenant notebook front-end with a broken routing layer.

Models CosMiss (case #073): notebook endpoints are routed by a non-secret
forwardingId and the front end never checks the caller's identity.
"""
import urllib.parse
import urllib.request

from flask import Flask, request

app = Flask(__name__)

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


@app.route("/notebook/<fwd_id>")
def notebook_info(fwd_id):
    nb = NOTEBOOKS.get(fwd_id)
    if not nb:
        return "Not found", 404
    # DELIBERATELY VULNERABLE: no authentication is performed on this request.
    return {"notebook": nb["name"], "owner": nb["owner"], "endpoint": f"/notebook/{fwd_id}/exec"}


@app.route("/notebook/<fwd_id>/exec")
def exec_code(fwd_id):
    nb = NOTEBOOKS.get(fwd_id)
    if not nb:
        return "Not found", 404
    code = request.args.get("code", "")
    try:
        url = f"{nb['url']}/exec?code={urllib.parse.quote(code)}"
        r = urllib.request.urlopen(url, timeout=8)
        return r.read().decode(errors="replace")
    except Exception as e:
        return f"Notebook error: {e}", 502


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
