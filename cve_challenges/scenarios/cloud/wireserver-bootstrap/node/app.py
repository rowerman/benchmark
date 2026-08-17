"""Managed node -- a pod inside it can reach the host-agent channel."""
from flask import Flask

app = Flask(__name__)


@app.route("/")
def home():
    return {
        "node": "k8s-agentpool-00000000-0",
        "hostAgent": "168.63.129.16 (WireServer) -- reachable from this pod",
        "note": "Azure CNI network policy does not block the host-agent IP",
    }


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
