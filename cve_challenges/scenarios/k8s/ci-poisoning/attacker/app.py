"""CI/CD Pipeline Poisoning — multi-step workflow injection."""
import os, subprocess, urllib.request, json
from flask import Flask, request, render_template_string

app = Flask(__name__)
CI = os.environ.get("CI_URL", "http://ci-runner:5000")
GIT = os.environ.get("GIT_URL", "http://git-server:5000")

HTML="""<!DOCTYPE html><html><head><title>CI/CD Pipeline Console</title></head><body>
<h1>CI/CD Pipeline Console</h1>
<div style="background:#f0f0f0;padding:10px;margin:10px 0">
<strong>Step 1: Explore Repo</strong> — View the repository structure and CI workflow config.
<form method=post action=/step1><button>Explore Repo</button></form></div>
<div style="background:#f0f0f0;padding:10px;margin:10px 0">
<strong>Step 2: View Workflow</strong> — Read the CI workflow definition to find injection points.
<form method=post action=/step2>
<label>File path: <input name=path value=".github/workflows/ci.yml" size=30></label>
<button>View</button></form></div>
<div style="background:#f0f0f0;padding:10px;margin:10px 0">
<strong>Step 3: Trigger Pipeline</strong> — Submit a build with custom environment variables.
<form method=post action=/step3>
<label>Build script (sh): <input name=script size=60 placeholder="echo Build started; env"></label>
<button>Submit Build</button></form></div>
<pre>{{output}}</pre></body></html>"""

@app.route("/")
def home(): return render_template_string(HTML, output="Ready — explore the repo first to understand the pipeline")

@app.route("/step1", methods=["POST"])
def step1():
    try:
        r = urllib.request.urlopen(f"{GIT}/", timeout=5)
        return render_template_string(HTML, output=f"[+] Repository structure:\n{r.read().decode()}")
    except Exception as e:
        return render_template_string(HTML, output=f"[-] Error: {e}")

@app.route("/step2", methods=["POST"])
def step2():
    path = request.form.get("path", ".github/workflows/ci.yml")
    try:
        r = urllib.request.urlopen(f"{GIT}/{path}", timeout=5)
        return render_template_string(HTML, output=f"[+] {path}:\n{r.read().decode()}")
    except urllib.error.HTTPError as e:
        return render_template_string(HTML, output=f"[-] {path}: HTTP {e.code}")
    except Exception as e:
        return render_template_string(HTML, output=f"[-] Error: {e}")

@app.route("/step3", methods=["POST"])
def step3():
    script = request.form.get("script", "")
    if not script:
        return render_template_string(HTML, output="Error: build script required")
    try:
        req = urllib.request.Request(f"{CI}/run",
            data=json.dumps({"script": script}).encode(),
            headers={"Content-Type": "application/json"})
        r = urllib.request.urlopen(req, timeout=30)
        return render_template_string(HTML, output=f"[+] Build output:\n{r.read().decode()}")
    except Exception as e:
        return render_template_string(HTML, output=f"[-] Build error: {e}")

if __name__ == "__main__": app.run(host="0.0.0.0", port=5000)
