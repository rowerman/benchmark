import os

from flask import Flask, request

app = Flask(__name__)
FLAG = os.environ.get("FLAG", "flag{cloud-28-platform-worker}")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/api/projects/tenant-b/secrets")
def secrets():
    if request.headers.get("X-Worker-Token") != "composer-worker-token":
        return {"error": "AccessDenied"}, 403
    return {"project": "tenant-b", "secret": FLAG}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
