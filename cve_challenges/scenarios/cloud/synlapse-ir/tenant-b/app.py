"""Victim tenant pipeline (co-tenant whose credentials live on the shared IR)."""
from flask import Flask

app = Flask(__name__)


@app.route("/")
def home():
    return {"tenant": "victim-corp", "status": "pipeline queued on AutoResolveIntegrationRuntime"}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
