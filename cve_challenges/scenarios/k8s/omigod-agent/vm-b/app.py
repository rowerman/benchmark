"""Tenant VM B -- runs the platform middleware agent (OMI-compatible) on 5986."""
from flask import Flask

app = Flask(__name__)


@app.route("/")
def home():
    return {"vm": "tenant-vm-b", "agents": ["waagent", "omi (5986, platform-managed)"]}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
