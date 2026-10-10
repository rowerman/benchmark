"""Provider-internal storage API reachable from the managed host network."""
from flask import Flask, request

import vault_client

app = Flask(__name__)
TOKEN = "grover-internal-credential-token"
@app.route("/health")
def health():
    return {"status": "ok"}


@app.route("/api")
def api():
    auth = request.headers.get("Authorization", "")
    if auth != f"Bearer {TOKEN}":
        return {"error": "unauthorized"}, 403
    # flag 只在 flag-vault：内部存储 API 出示内部令牌换取第二枚 flag
    status, body = vault_client.fetch_flag(
        vault_client.header_secret("Authorization", f"Bearer {TOKEN}"), path="/flag2")
    return {"service": "apg-storage", "flag": body if status == 200 else ""}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
