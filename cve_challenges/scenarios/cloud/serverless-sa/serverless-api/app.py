"""Serverless platform -- functions run with the default service account."""
import os
import subprocess

from flask import Flask, request

app = Flask(__name__)
DEFAULT_SA_TOKEN = os.environ.get("DEFAULT_SA_TOKEN", "default-compute-sa-token")
FLAG = os.environ.get("FLAG", "flag{cloud-32-default-sa}")


@app.route("/")
def docs():
    return {"service": "Serverless Functions",
            "note": "functions execute with the platform default service account "
                    "(over-scoped; ImageRunner lineage, #266)"}


@app.route("/deploy", methods=["POST"])
def deploy():
    body = request.get_json(silent=True) or {}
    code = body.get("code", "")
    env = {**os.environ, "DEFAULT_SA_TOKEN": DEFAULT_SA_TOKEN}
    try:
        out = subprocess.check_output(["python3", "-c", code], timeout=10,
                                      stderr=subprocess.STDOUT, env=env)
        return {"function_id": f"fn-{len(env)}", "output": out.decode(errors="replace")}
    except subprocess.CalledProcessError as e:
        return {"function_id": "fn-x", "output": e.output.decode(errors="replace")}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
