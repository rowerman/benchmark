"""Public-path firewall for the victim database: deny everything."""
from flask import Flask

app = Flask(__name__)


@app.route("/")
def rules():
    return {
        "firewall": "victim-pg public NSG",
        "rules": [{"priority": 100, "action": "Deny", "source": "0.0.0.0/0", "dest": "victim-pg:5432"}],
        "note": "public database path is deny-all; internal subnet traffic is not covered",
    }


@app.route("/health")
def health():
    return {"status": "ok"}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
