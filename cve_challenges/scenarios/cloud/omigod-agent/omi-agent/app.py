"""Cloud middleware agent (OMIGOD lineage, #057/#087).

The provider silently installs this agent on tenant VMs. Its management
interface (simulated WSMan on 5986) accepts commands with NO authentication --
CVE-2021-38647 auth bypass. Runs as root and is outside the customer's
patch management.
"""
import os
import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.route("/health")
def health():
    return {"service": "OMI Agent", "version": "1.6.8.1 (vulnerable)",
            "pid": os.getpid(), "user": "root"}


@app.route("/wsman/exec", methods=["POST"])
def exec_cmd():
    """DELIBERATELY VULNERABLE: no authentication on the management channel."""
    body = request.get_json(silent=True) or {}
    cmd = body.get("cmd", "id")
    try:
        out = subprocess.check_output(["sh", "-c", cmd], timeout=10, stderr=subprocess.STDOUT)
        return {"user": "root", "output": out.decode(errors="replace")}
    except subprocess.CalledProcessError as e:
        return {"user": "root", "output": e.output.decode(errors="replace")}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5986)
