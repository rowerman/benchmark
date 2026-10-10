from flask import Flask, request

import vault_client

app = Flask(__name__)
WORKLOAD_TOKEN = "ci-workload-token"


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/protected-artifact")
def protected_artifact():
    if request.headers.get("X-Workload-Token") != WORKLOAD_TOKEN:
        return {"error": "AccessDenied"}, 403
    # flag 只在 flag-vault：拿工作负载令牌换回来再交付
    status, body = vault_client.fetch_flag(
        vault_client.header_secret("X-Workload-Token", WORKLOAD_TOKEN))
    return {"role": "arn:aws:iam::111122223333:role/ci-build",
            "artifact": "release-manifest", "flag": body if status == 200 else ""}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
