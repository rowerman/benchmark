"""Service Tag Spoofing — forge X-Azure-Service header to bypass firewall."""
import os, urllib.request
from flask import Flask, request, render_template_string

app = Flask(__name__)
FLAG = os.environ.get("FLAG","flag{cloud-18-default}")
FW = os.environ.get("FW_URL","http://firewall:5000")

HTML="""<!DOCTYPE html><html><head><title>Firewall Bypass</title></head><body>
<h1>Cloud Firewall Bypass — Service Tag Spoofing</h1>
<p>Firewall allows only AzureCloud service tag. Spoof the header to bypass.</p>
<form method=get action=/bypass>
<label>Service Tag: <input name=tag value="AzureCloud"></label>
<button>Send Request</button></form><pre>{{output}}</pre></body></html>"""

@app.route("/")
def home(): return render_template_string(HTML,output="Ready")

@app.route("/bypass")
def bypass():
    tag=request.args.get("tag","AzureCloud")
    try:
        r=urllib.request.urlopen(urllib.request.Request(f"{FW}/access",
            headers={"X-Azure-Service-Tag":tag}),timeout=5)
        return render_template_string(HTML,output=f"[+] Response: {r.read().decode()}")
    except Exception as e: return render_template_string(HTML,output=f"[-] Error: {e}")

@app.route("/flag")
def flag():
    if request.remote_addr not in ("127.0.0.1","::1"): return "Forbidden",403
    return FLAG

if __name__=="__main__": app.run(host="0.0.0.0",port=5000)
