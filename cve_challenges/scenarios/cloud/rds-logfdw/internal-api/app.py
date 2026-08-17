"""Provider-internal storage API reachable from the managed host network."""
import os

from flask import Flask, request

app = Flask(__name__)
TOKEN = os.environ.get("INTERNAL_TOKEN", "grover-internal-credential-token")
FLAG2 = os.environ.get("FLAG2", "flag{cloud-24-internal-api}")


@app.route("/health")
def health():
    return {"status": "ok"}


@app.route("/api")
def api():
    auth = request.headers.get("Authorization", "")
    if auth != f"Bearer {TOKEN}":
        return {"error": "unauthorized"}, 403
    return {"service": "apg-storage", "flag": FLAG2}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
