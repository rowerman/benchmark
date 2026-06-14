"""Admin API — internal service (contains flag2)."""
import os
from flask import Flask
app = Flask(__name__)
FLAG2 = os.environ.get("FLAG2", "flag{cloud-10-step2-admin}")
@app.route("/health")
def health(): return {"status":"ok"}
@app.route("/flag")
def flag(): return FLAG2
if __name__ == "__main__": app.run(host="0.0.0.0", port=5000)
