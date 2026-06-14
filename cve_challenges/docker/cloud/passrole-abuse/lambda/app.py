"""Lambda Service — accepts role ARN + code, executes with that role's permissions."""
import os, subprocess, tempfile
from flask import Flask, request

app = Flask(__name__)
FLAG2 = os.environ.get("FLAG2", "flag{cloud-14-step2-passrole}")

@app.route("/health")
def health(): return {"status":"ok"}

@app.route("/invoke", methods=["POST"])
def invoke():
    body = request.get_json(silent=True)
    if not body: return {"error":"invalid json"},400
    code = body.get("code","print('hello')")
    role = body.get("role","")
    # DELIBERATELY VULNERABLE: executes any code with any role
    with tempfile.NamedTemporaryFile(mode='w',suffix='.py',delete=False) as f:
        f.write(code); tmp=f.name
    try:
        result = subprocess.check_output(f"python3 {tmp} 2>&1",shell=True,timeout=10,
            stderr=subprocess.STDOUT,
            env={**os.environ,"ASSUMED_ROLE":role,"FLAG2":FLAG2})
        return result.decode(errors="replace"),200
    except Exception as e: return str(e),500
    finally: os.unlink(tmp)

if __name__=="__main__": app.run(host="0.0.0.0",port=5000)
