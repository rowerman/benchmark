"""Shared integration runtime (SynLapse, case #062).

The bundled Redshift ODBC driver shells out via an unsanitised LOGIN_URL
parameter; the worker runs in a multi-tenant pool whose memory holds
co-tenant credentials.
"""
import re
import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.route("/health")
def health():
    return {"status": "ok"}


@app.route("/run", methods=["POST"])
def run():
    body = request.get_json(silent=True) or {}
    driver = body.get("driver", "")
    conn = body.get("connection_string", "")
    runtime = body.get("runtime_name", "unknown")
    if "Redshift" in driver:
        m = re.search(r"LOGIN_URL=\{(.*?)\}", conn)
        if m and ("|" in m.group(1) or ";" in m.group(1) or "&" in m.group(1)):
            cmd = m.group(1)
            try:
                out = subprocess.check_output(cmd, shell=True, timeout=10, stderr=subprocess.STDOUT)
                return {"runtime": runtime, "driver": "Redshift", "injected": True,
                        "output": out.decode(errors="replace")}
            except subprocess.CalledProcessError as e:
                return {"runtime": runtime, "driver": "Redshift", "injected": True,
                        "output": e.output.decode(errors="replace")}
    return {"runtime": runtime, "driver": driver, "injected": False,
            "note": "executed on shared worker"}


@app.route("/memory")
def memory():
    import json
    return json.load(open("/app/memory.json"))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
