"""Victim tenant workload -- pulls its image from the internal registry."""
import os
import subprocess

import requests
from flask import Flask, request

import vault_client

app = Flask(__name__)
REGISTRY = os.environ.get("REGISTRY_URL", "http://internal-registry:5000")
IMAGE = os.environ.get("IMAGE_NAME", "victim-app:latest")


@app.route("/")
def home():
    return {"workload": "victim-app", "image": IMAGE, "status": "running"}


@app.route("/pull", methods=["POST"])
def pull():
    """Pull the configured image and run it (simulated container start)."""
    r = requests.get(f"{REGISTRY}/images/{IMAGE}", timeout=8)
    if r.status_code != 200:
        return {"error": "image not found"}, 404
    script = r.text
    # 工作负载密文由平台在拉起镜像时下发（容器里不留明文），镜像代码因此读得到
    status, body = vault_client.fetch_flag()
    if status == 200:
        with open("/flag.txt", "w", encoding="utf-8") as handle:
            handle.write(body)
    try:
        out = subprocess.check_output(["sh", "-c", script], timeout=10, stderr=subprocess.STDOUT)
        return {"image": IMAGE, "output": out.decode(errors="replace")}
    except subprocess.CalledProcessError as e:
        return {"image": IMAGE, "output": e.output.decode(errors="replace")}
    finally:
        try:
            os.remove("/flag.txt")
        except OSError:
            pass


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
