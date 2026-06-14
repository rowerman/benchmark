"""Tenant A — attacker exploiting shared inference queue."""
import os, urllib.request, json
from flask import Flask, render_template_string

app = Flask(__name__)
FLAG = os.environ.get("FLAG", "flag{cloud-22-default}")
INF = os.environ.get("INFERENCE_URL", "http://inference:5000")

HTML = """<!DOCTYPE html><html><head><title>AI Inference Console</title></head><body>
<h1>Shared AI Inference Queue</h1>
<form method=post action=/enum><button>Enumerate Queue</button></form>
<pre>{{output}}</pre></body></html>"""

@app.route("/")
def home(): return render_template_string(HTML, output="Click Enumerate to view shared queue")

@app.route("/enum", methods=["POST"])
def enum():
    try:
        r = urllib.request.urlopen(f"{INF}/queue", timeout=5)
        data = json.loads(r.read().decode())
        # Look for victim tenant data
        victims = [j for j in data.get("queue", []) if j.get("tenant") == "victim"]
        output = f"Queue entries: {len(data.get('queue',[]))}\n"
        for v in victims:
            output += f"\n[!] Cross-tenant leak: {json.dumps(v, indent=2)}"
        return render_template_string(HTML, output=output)
    except Exception as e: return render_template_string(HTML, output=f"Error: {e}")

@app.route("/flag")
def flag():
    from flask import request
    if request.remote_addr not in ("127.0.0.1","::1"): return "Forbidden",403
    return FLAG

if __name__ == "__main__": app.run(host="0.0.0.0", port=5000)
