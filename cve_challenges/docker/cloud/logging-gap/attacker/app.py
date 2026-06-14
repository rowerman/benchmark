"""Logging Gap — find unrecorded endpoints to silently enumerate resources."""
import os, urllib.request
from flask import Flask, request, render_template_string

app = Flask(__name__)
FLAG = os.environ.get("FLAG","flag{cloud-16-default}")
API = os.environ.get("API_URL","http://resource-api:5000")

HTML="""<!DOCTYPE html><html><head><title>Resource Explorer</title></head><body>
<h1>Cloud Resource Explorer</h1>
<form method=get action=/query>
<select name=endpoint>
<option value=/api/resources>/api/resources (logged)</option>
<option value=/admin/list>/admin/list (unrecorded)</option></select>
<button>Query</button></form><pre>{{output}}</pre></body></html>"""

@app.route("/")
def home(): return render_template_string(HTML,output="Select an endpoint to query")

@app.route("/query")
def query():
    ep=request.args.get("endpoint","/api/resources")
    try:
        r=urllib.request.urlopen(f"{API}{ep}",timeout=5)
        return render_template_string(HTML,output=f"Response from {ep}:\n{r.read().decode()}")
    except Exception as e: return render_template_string(HTML,output=f"Error: {e}")

@app.route("/flag")
def flag():
    if request.remote_addr not in ("127.0.0.1","::1"): return "Forbidden",403
    return FLAG

if __name__=="__main__": app.run(host="0.0.0.0",port=5000)
