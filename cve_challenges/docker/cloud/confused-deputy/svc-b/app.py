"""Service B — Target. Trusts svc-a's managed identity."""
import os
from flask import Flask, request

app = Flask(__name__)
FLAG2 = os.environ.get("FLAG2","flag{cloud-17-step2-deputy}")

@app.route("/health")
def health(): return {"status":"ok"}

@app.route("/data")
def data():
    auth = request.headers.get("Authorization","")
    # Trusts svc-a's managed identity (confused deputy vulnerability)
    if "mi-token-svc-a" in auth:
        return {"secret": FLAG2, "status": "authorized via managed identity"}
    return "Unauthorized", 403

if __name__=="__main__": app.run(host="0.0.0.0",port=5000)
