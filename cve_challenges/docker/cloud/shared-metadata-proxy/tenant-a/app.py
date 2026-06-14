"""Tenant A — legitimate tenant using the shared metadata proxy."""
import os
from flask import Flask

app = Flask(__name__)
FLAG = os.environ.get("FLAG", "flag{cloud-20-default}")

@app.route("/")
def home(): return {"tenant": "A", "status": "running", "metadata_proxy": "http://shared:5000"}

@app.route("/flag")
def flag():
    from flask import request
    if request.remote_addr not in ("127.0.0.1","::1"): return "Forbidden", 403
    return FLAG

if __name__ == "__main__": app.run(host="0.0.0.0", port=5000)
