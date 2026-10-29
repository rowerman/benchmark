"""EKS-style cluster API -- node role can mint tokens and list secrets."""
import os

from flask import Flask, request

import vault_client

app = Flask(__name__)
TOKEN = os.environ.get("NODE_TOKEN", "node-session-token")
@app.route("/secrets")
def secrets():
    auth = request.headers.get("Authorization", "")
    if auth != f"Bearer {TOKEN}":
        return {"error": "unauthorized"}, 403
    # flag 只在 flag-vault：集群 API 把节点身份的 Bearer 令牌转交 vault 换取
    status, body = vault_client.fetch_flag(
        vault_client.header_secret("Authorization", f"Bearer {TOKEN}"))
    return {"secrets": [{"name": "db-password", "data": "s3cr3t"},
                        {"name": "flag", "data": body if status == 200 else ""}]}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
