from flask import Flask, request

import vault_client

app = Flask(__name__)
@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/api/projects/tenant-b/secrets")
def secrets():
    if request.headers.get("X-Worker-Token") != "composer-worker-token":
        return {"error": "AccessDenied"}, 403
    # flag 只在 flag-vault：平台密钥库按工作负载地址交付
    status, body = vault_client.fetch_flag()
    return {"project": "tenant-b", "secret": body if status == 200 else ""}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
