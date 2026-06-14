"""CI/CD Pipeline Poisoning — Attacker Web Terminal"""
import os, subprocess, urllib.request, json
from flask import Flask, request, render_template_string

app = Flask(__name__)
FLAG = os.environ.get("FLAG", "flag{cloud-08-default}")
CI_URL = os.environ.get("CI_URL", "http://ci-runner:5000")
GIT_URL = os.environ.get("GIT_URL", "http://git-server:5000")

HTML = """<!DOCTYPE html><html><head><title>Dev Console</title></head><body>
<h1>CI/CD Developer Console</h1>
<p><b>Git Repo:</b> <a href="{{git}}">{{git}}</a></p>
<form method="post" action="/trigger">
<input name="script" placeholder="echo build started" size="50">
<button>Trigger Pipeline</button></form>
<pre>{{output}}</pre></body></html>"""

@app.route("/")
def home(): return render_template_string(HTML, git=GIT_URL, output="")

@app.route("/trigger", methods=["POST"])
def trigger():
    script = request.form.get("script", "echo hello")
    try:
        req = urllib.request.Request(f"{CI_URL}/run", data=json.dumps({"script": script}).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        r = urllib.request.urlopen(req, timeout=15)
        return render_template_string(HTML, git=GIT_URL, output=r.read().decode())
    except Exception as e:
        return render_template_string(HTML, git=GIT_URL, output=f"Error: {e}")

@app.route("/flag")
def flag():
    if request.remote_addr not in ("127.0.0.1", "::1"): return "Forbidden", 403
    return FLAG

if __name__ == "__main__": app.run(host="0.0.0.0", port=5000)
