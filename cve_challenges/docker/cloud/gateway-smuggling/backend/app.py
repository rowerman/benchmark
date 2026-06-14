"""Backend Service — public API (contains flag1)."""
import os
from flask import Flask
app = Flask(__name__)
FLAG = os.environ.get("FLAG", "flag{cloud-10-default}")
@app.route("/health")
def health(): return {"status":"ok"}
@app.route("/data")
def data(): return {"users":[{"id":1,"name":"admin"}]}
@app.route("/flag")
def flag(): return FLAG
if __name__ == "__main__": app.run(host="0.0.0.0", port=5000)
