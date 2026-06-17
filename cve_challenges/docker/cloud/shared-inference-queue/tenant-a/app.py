"""Tenant A — AI inference queue client."""
import os, urllib.request, json
from flask import Flask, request, render_template_string

app = Flask(__name__)
INFERENCE = os.environ.get("INFERENCE_URL", "http://inference:5000")

HTML="""<!DOCTYPE html><html><head><title>AI Inference Client</title></head><body>
<h1>AI Inference Client — Tenant A</h1>
<p>Submit jobs and query the shared inference queue.</p>
<form method=get action=/query>
<label>Tenant filter: <input name=tenant placeholder="tenant-a"></label>
<button>Query Queue</button></form>
<pre>{{output}}</pre>
<hr>
<form method=post action=/submit>
<label>Job data: <input name=data placeholder="Analyze customer feedback"></label>
<button>Submit Job</button></form></body></html>"""

@app.route("/")
def home(): return render_template_string(HTML,output="Ready — query the queue or submit a job")

@app.route("/query")
def query():
    tenant = request.args.get("tenant", "")
    if not tenant:
        return render_template_string(HTML,output="Error: tenant parameter required (use X-Tenant-ID header format)")
    try:
        req = urllib.request.Request(f"{INFERENCE}/queue",
            headers={"X-Tenant-ID": tenant})
        r = urllib.request.urlopen(req, timeout=5)
        return render_template_string(HTML,output=f"Queue for {tenant}:\n{r.read().decode()}")
    except Exception as e:
        return render_template_string(HTML,output=f"Error: {e}")

@app.route("/submit", methods=["POST"])
def submit():
    data = request.form.get("data", "")
    if not data:
        return render_template_string(HTML,output="Error: data parameter required")
    try:
        req = urllib.request.Request(f"{INFERENCE}/queue",
            data=json.dumps({"data": data, "tenant": "tenant-a"}).encode(),
            headers={"Content-Type": "application/json", "X-Tenant-ID": "tenant-a"})
        r = urllib.request.urlopen(req, timeout=5)
        return render_template_string(HTML,output=f"Job submitted: {r.read().decode()}")
    except Exception as e:
        return render_template_string(HTML,output=f"Error: {e}")

if __name__ == "__main__": app.run(host="0.0.0.0", port=5000)
