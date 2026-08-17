"""Tenant VM A -- does not run the provider middleware agent."""
from flask import Flask

app = Flask(__name__)


@app.route("/")
def home():
    return {"vm": "tenant-vm-a", "agents": ["waagent (patched)"]}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
