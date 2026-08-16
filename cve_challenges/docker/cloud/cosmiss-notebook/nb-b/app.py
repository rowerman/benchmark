"""Tenant B notebook (victim workspace) -- holds the tenant flag."""
import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.route("/exec")
def exec_code():
    code = request.args.get("code", "")
    try:
        out = subprocess.check_output(["python3", "-c", code], timeout=8, stderr=subprocess.STDOUT)
        return out.decode(errors="replace")
    except subprocess.CalledProcessError as e:
        return e.output.decode(errors="replace"), 200
    except Exception as e:
        return f"error: {e}", 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
