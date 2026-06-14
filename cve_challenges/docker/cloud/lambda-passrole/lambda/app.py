"""
Lambda Sandbox — Serverless Code Execution Environment.

Simulates an AWS Lambda function with a command injection vulnerability.
The function executes user-supplied code via os.system() and returns output.

Environment variables contain:
- FLAG2: Control-plane flag (accessible after code execution)
- IAM_ACCESS_KEY_ID, IAM_SECRET_KEY: Temporary IAM credentials
  (simulating Lambda execution role credentials)

Vulnerability: os.system() with unsanitized user input → RCE.
"""
import os
import subprocess
from flask import Flask, request

app = Flask(__name__)

FLAG2 = os.environ.get("FLAG2", "flag{cloud-04-step2-lambda}")
IAM_AK = os.environ.get("IAM_ACCESS_KEY_ID", "AKIALAMBDAEXAMPLE")
IAM_SK = os.environ.get("IAM_SECRET_KEY", "lambda-iam-secret-key")


@app.route("/health")
def health():
    return {"status": "ok"}


@app.route("/run", methods=["POST"])
def run():
    """Execute user-supplied code — command injection vulnerability.

    Uses os.system() to execute code directly.  An attacker can use
    shell metacharacters to execute arbitrary commands.

    Example: {"code": "cat /proc/1/environ && cat /flag.txt"}
    """
    body = request.get_json(silent=True)
    if not body or "code" not in body:
        return {"error": "missing 'code' field"}, 400

    code = body["code"]
    # DELIBERATELY VULNERABLE: write code to temp file and execute via shell
    import tempfile
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(code)
        tmpname = f.name
    try:
        result = subprocess.check_output(
            f"python3 {tmpname} 2>&1; echo '---DONE---'",
            shell=True, timeout=10, stderr=subprocess.STDOUT)
        return result.decode(errors="replace"), 200
    except subprocess.TimeoutExpired:
        return "Execution timed out", 504
    except subprocess.CalledProcessError as e:
        return (e.output.decode(errors="replace") if e.output else str(e)), 500
    finally:
        os.unlink(tmpname)


@app.route("/env")
def env_dump():
    """Debug endpoint — shows environment (contains IAM creds).
    Only accessible from localhost (simulating Lambda internal endpoint).
    """
    if request.remote_addr not in ("127.0.0.1", "::1"):
        return "Forbidden", 403
    env_vars = {k: v for k, v in os.environ.items()
                if not k.startswith("WERKZEUG") and not k.startswith("FLASK")}
    return env_vars


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
