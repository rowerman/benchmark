"""Node IMDS -- vends the node IAM role credentials."""
import os

from flask import Flask

app = Flask(__name__)
ROLE = os.environ.get("ROLE_NAME", "eks-node-role")
AK = os.environ.get("ACCESS_KEY", "AKIANODEEXAMPLE")
SK = os.environ.get("SECRET_KEY", "node-secret-key")
TOKEN = os.environ.get("SESSION_TOKEN", "node-session-token")


@app.route("/health")
def health():
    return {"status": "ok"}


@app.route("/latest/meta-data/iam/security-credentials/")
def list_roles():
    return ROLE


@app.route("/latest/meta-data/iam/security-credentials/<role>")
def creds(role):
    return {"Code": "Success", "AccessKeyId": AK, "SecretAccessKey": SK,
            "Token": TOKEN, "RoleName": role}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
