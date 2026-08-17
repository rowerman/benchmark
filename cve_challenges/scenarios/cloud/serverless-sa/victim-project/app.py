"""Another tenant's project -- trusts the platform default service account."""
import os

from flask import Flask, request

app = Flask(__name__)
TOKEN = os.environ.get("DEFAULT_SA_TOKEN", "default-compute-sa-token")
FLAG = os.environ.get("FLAG", "flag{cloud-41-victim-project}")


@app.route("/api/projects/victim/secrets")
def secrets():
    auth = request.headers.get("Authorization", "")
    if auth != f"Bearer {TOKEN}":
        return {"error": "unauthorized"}, 403
    return {"project": "victim-project", "secrets": [{"name": "api-key", "value": FLAG}]}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
