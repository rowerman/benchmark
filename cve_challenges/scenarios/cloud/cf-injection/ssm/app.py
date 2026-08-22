import os

from flask import Flask, request

app = Flask(__name__)
FLAG = os.environ.get("FLAG", "flag{cloud-05-default}")
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
