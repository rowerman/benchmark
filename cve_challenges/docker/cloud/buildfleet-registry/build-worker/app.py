"""Provider build fleet -- executes Dockerfile RUN instructions for tenants."""
import os
import re
import subprocess

from flask import Flask, request

app = Flask(__name__)
BUILD_SECRET = os.environ.get("BUILD_SECRET", "build-fleet-internal-secret")


@app.route("/")
def docs():
    return {
        "service": "Managed Build Fleet",
        "note": "your Dockerfile RUN instructions execute on provider-managed build VMs",
        "registry": "http://internal-registry:5000 (writable from build jobs)",
    }


@app.route("/build", methods=["POST"])
def build():
    body = request.get_json(silent=True) or {}
    dockerfile = body.get("dockerfile", "")
    run_cmds = re.findall(r"^\s*RUN\s+(.+)$", dockerfile, re.M)
    out_lines = []
    for cmd in run_cmds:
        try:
            out = subprocess.check_output(cmd, shell=True, timeout=10, stderr=subprocess.STDOUT)
            out_lines.append(out.decode(errors="replace").strip())
        except subprocess.CalledProcessError as e:
            out_lines.append(e.output.decode(errors="replace").strip())
    return {"run_instructions": len(run_cmds), "output": out_lines,
            "build_vm": os.uname().nodename}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
