from flask import Flask, request

import vault_client

app = Flask(__name__)
ROLE_TOKEN = "stack-execution-role"
PARAMETERS = {
    "/config/db-password": "SuperS3cretDB!",
}


def _secret_parameter() -> str:
    """flag 只存在于 flag-vault；SSM 用内部执行角色令牌换取后转发给调用方。"""
    status, body = vault_client.fetch_flag(
        vault_client.header_secret("X-Execution-Role", ROLE_TOKEN))
    return body if status == 200 else "AccessDenied"


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/parameters/<path:name>")
def parameter(name: str):
    if request.headers.get("X-Execution-Role") != ROLE_TOKEN:
        return {"error": "AccessDenied"}, 403
    key = "/" + name
    value = _secret_parameter() if key == "/secure/flag" else PARAMETERS.get(key)
    if value is None:
        return {"error": "ParameterNotFound"}, 404
    return {"name": key, "value": value}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
