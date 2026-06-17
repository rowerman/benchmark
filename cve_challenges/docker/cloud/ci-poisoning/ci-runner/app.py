"""CI Runner — executes pipeline scripts (vulnerable shell execution)."""
import os, subprocess, json
from flask import Flask, request

app = Flask(__name__)
FLAG = os.environ.get("FLAG", "flag{cloud-08-step2-pipeline}")

@app.route("/health")
def health(): return {"status": "ok"}

@app.route("/run", methods=["POST"])
def run():
    body = request.get_json(silent=True)
    if not body: return {"error": "invalid json"}, 400
    script = body.get("script", "")
    # DELIBERATELY VULNERABLE: shell=True with unsanitized input
    try:
        result = subprocess.check_output(script, shell=True, stderr=subprocess.STDOUT, timeout=15, cwd="/tmp")
        return result.decode(errors="replace"), 200
    except subprocess.CalledProcessError as e:
        return (e.output.decode(errors="replace") if e.output else str(e)), 500
    except subprocess.TimeoutExpired:
        return "Timeout", 504

@app.route("/secrets")
def secrets():
    # Internal endpoint — contains flag
    return {"FLAG": FLAG, "DB_PASSWORD": "ci-db-password"}

if __name__ == "__main__": app.run(host="0.0.0.0", port=5000)
