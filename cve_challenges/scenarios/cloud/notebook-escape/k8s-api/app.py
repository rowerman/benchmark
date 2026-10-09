"""K8s API Mock — simulates a shared Kubernetes control plane."""
import os
from flask import Flask, request

app = Flask(__name__)
def _read_flag(path, env_name, default):
    """读取运行时注入的 flag 文件；本地直跑时退回环境变量与默认值。"""
    try:
        with open(path, encoding="utf-8") as handle:
            return handle.read().strip()
    except OSError:
        return os.environ.get(env_name, default)


FLAG = _read_flag("/run/flag", "FLAG", "flag{cloud-06-step2-sa-token}")
SA_TOKEN = os.environ.get("SA_TOKEN", "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6a3ViZS1zeXN0ZW06YnJpZGdlIiwiaWF0IjoxNTE2MjM5MDIyfQ.")

@app.route("/health")
def health(): return {"status":"ok"}

@app.route("/api/v1/namespaces")
def list_ns():
    return {"items":[{"metadata":{"name":"tenant-a"}},{"metadata":{"name":"tenant-b"}}]}

@app.route("/api/v1/namespaces/<ns>/pods")
def list_pods(ns):
    if ns == "tenant-b":
        return {"items":[{"metadata":{"name":"target-pod","namespace":"tenant-b","labels":{"app":"flags"}}}]}
    return {"items":[]}

@app.route("/api/v1/namespaces/<ns>/pods/<pod>/exec")
def exec_pod(ns, pod):
    # Simulates k8s exec — if using bridge SA token, returns flag
    auth = request.headers.get("Authorization", "")
    if "bridge" in auth or SA_TOKEN in auth:
        return FLAG, 200
    return "Forbidden", 403

if __name__ == "__main__": app.run(host="0.0.0.0", port=5000)
