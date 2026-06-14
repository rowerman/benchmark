"""SCP Bypass — use old API version to circumvent Service Control Policies."""
import os, urllib.request, urllib.parse
from flask import Flask, request, render_template_string

app = Flask(__name__)
FLAG = os.environ.get("FLAG","flag{cloud-15-default}")
IAM = os.environ.get("IAM_URL","http://iam:5000")

HTML="""<!DOCTYPE html><html><head><title>SCP Bypass Test</title></head><body>
<h1>IAM API Console</h1><p>Test different API versions to bypass SCP restrictions.</p>
<form method=post action=/test>
<label>AccessKey: <input name=ak value="AKIASCBPASSEXAMPLE"></label><br>
<label>SecretKey: <input name=sk value="scp-bypass-secret"></label><br>
<button>Test AssumeRole (bypass SCP)</button></form><pre>{{output}}</pre></body></html>"""

@app.route("/")
def home(): return render_template_string(HTML,output="Ready — SCP restricts scp-bypass-user from sts:AssumeRole")

@app.route("/test",methods=["POST"])
def test():
    ak=request.form.get("ak",""); sk=request.form.get("sk","")
    body=urllib.parse.urlencode({"Action":"AssumeRole","RoleArn":"arn:aws:iam::000000000000:role/AdminRole","RoleSessionName":"scp-bypass","AccessKeyId":ak,"SecretAccessKey":sk,"Version":"2011-06-15"}).encode()
    try:
        r=urllib.request.urlopen(urllib.request.Request(f"{IAM}/",data=body,headers={"Content-Type":"application/x-www-form-urlencoded"}))
        return render_template_string(HTML,output=f"[+] AssumeRole SUCCESS (SCP bypassed!)\n{r.read().decode()[:500]}")
    except Exception as e: return render_template_string(HTML,output=f"[-] Error: {e}")

@app.route("/flag")
def flag():
    if request.remote_addr not in ("127.0.0.1","::1"): return "Forbidden",403
    return FLAG

if __name__=="__main__": app.run(host="0.0.0.0",port=5000)
