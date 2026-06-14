"""S3 Target — cross-account protected resource."""
import os
from flask import Flask
app = Flask(__name__)
FLAG2 = os.environ.get("FLAG2", "flag{cloud-12-step2-cross-account}")
@app.route("/health")
def health(): return {"status":"ok"}
@app.route("/flag.txt")
def flag(): return FLAG2
if __name__ == "__main__": app.run(host="0.0.0.0", port=5000)
