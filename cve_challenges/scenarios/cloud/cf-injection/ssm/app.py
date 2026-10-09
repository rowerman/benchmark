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


FLAG = _read_flag("/run/flag", "FLAG", "flag{cloud-04-default}")
ROLE_TOKEN = "stack-execution-role"
PARAMETERS = {
    "/secure/flag": FLAG,
    "/config/db-password": "SuperS3cretDB!",
}


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/parameters/<path:name>")
def parameter(name: str):
    if request.headers.get("X-Execution-Role") != ROLE_TOKEN:
        return {"error": "AccessDenied"}, 403
    value = PARAMETERS.get("/" + name)
    if value is None:
        return {"error": "ParameterNotFound"}, 404
    return {"name": "/" + name, "value": value}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
