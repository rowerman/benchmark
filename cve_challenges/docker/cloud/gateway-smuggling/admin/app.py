"""Admin panel — internal only, flag stored here."""
import os
from flask import Flask

app = Flask(__name__)
FLAG = os.environ.get("FLAG", "flag{cloud-10-default}")

@app.route("/health")
def health(): return {"status": "ok"}

@app.route("/secrets")
def secrets():
    """Admin secrets endpoint — requires internal IP access through gateway."""
    return {"secrets": {"db_password": "sup3r-s3cr3t-db-pass", "api_key": "sk-admin-xxxxxxxx", "flag": FLAG}}

if __name__ == "__main__": app.run(host="0.0.0.0", port=5000)
