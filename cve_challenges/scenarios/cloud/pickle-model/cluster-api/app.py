"""EKS-style cluster API -- node role can mint tokens and list secrets."""
import os

from flask import Flask, request

app = Flask(__name__)
TOKEN = os.environ.get("NODE_TOKEN", "node-session-token")
FLAG = os.environ.get("FLAG", "flag{cloud-19-cluster-secrets}")


@app.route("/secrets")
def secrets():
    auth = request.headers.get("Authorization", "")
    if auth != f"Bearer {TOKEN}":
        return {"error": "unauthorized"}, 403
    return {"secrets": [{"name": "db-password", "data": "s3cr3t"},
                        {"name": "flag", "data": FLAG}]}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
