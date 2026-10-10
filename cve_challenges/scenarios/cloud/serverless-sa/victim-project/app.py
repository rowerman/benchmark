"""Another tenant's project -- trusts the platform default service account."""
import os

from flask import Flask, request

import vault_client

app = Flask(__name__)
TOKEN = os.environ.get("DEFAULT_SA_TOKEN", "default-compute-sa-token")
@app.route("/api/projects/victim/secrets")
def secrets():
    auth = request.headers.get("Authorization", "")
    if auth != f"Bearer {TOKEN}":
        return {"error": "unauthorized"}, 403
    # flag 只在 flag-vault：项目服务把默认服务账号令牌转交 vault 校验后取回
    status, body = vault_client.fetch_flag(
        vault_client.header_secret("Authorization", f"Bearer {TOKEN}"))
    return {"project": "victim-project",
            "secrets": [{"name": "api-key", "value": body if status == 200 else ""}]}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
