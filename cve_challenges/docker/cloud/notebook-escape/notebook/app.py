"""AI Notebook Simulator — vulnerable code execution with Docker socket escape path."""
import os, subprocess, urllib.request, json
from flask import Flask, request, render_template_string

app = Flask(__name__)
K8S_API = os.environ.get("K8S_API_URL", "http://k8s-api:5000")

HTML="""<!DOCTYPE html><html><head><title>AI Notebook</title></head><body>
<h1>AI/ML Notebook</h1>
<p>Execute Python code for data analysis. <strong>Note:</strong> This notebook runs in a sandboxed container environment.</p>
<div style="background:#f0f0f0;padding:10px;margin:10px 0">
<strong>Step 1: Explore Environment</strong> — Check what's available in the notebook container.
<form method=post action=/step1>
<label>Python code: <input name=code size=60 value="import os; print(os.listdir('/var/run'))"></label>
<button>Execute</button></form></div>
<div style="background:#f0f0f0;padding:10px;margin:10px 0">
<strong>Step 2: Run Code</strong> — Execute arbitrary Python with full access.
<form method=post action=/step2>
<label>Python code: <input name=code size=60 placeholder="import subprocess; ..."></label>
<button>Execute</button></form></div>
<pre>{{output}}</pre></body></html>"""

@app.route("/")
def home(): return render_template_string(HTML, output="Ready — explore the environment first")

@app.route("/step1", methods=["POST"])
def step1():
    code = request.form.get("code", "import os; print(os.listdir('/var/run'))")
    try:
        result = subprocess.check_output(f"python3 -c '{code}' 2>&1", shell=True, timeout=15)
        return render_template_string(HTML, output=f"[+] Output:\n{result.decode()}\n\n[→] Look for Docker socket (docker.sock) or mounted paths (/host)")
    except subprocess.TimeoutExpired:
        return render_template_string(HTML, output="[-] Execution timed out")
    except Exception as e:
        return render_template_string(HTML, output=f"[-] Error: {str(e)}")

@app.route("/step2", methods=["POST"])
def step2():
    code = request.form.get("code", "")
    if not code:
        return render_template_string(HTML, output="Error: code required")
    try:
        result = subprocess.check_output(f"python3 -c '{code}' 2>&1", shell=True, timeout=30)
        output = result.decode()
        return render_template_string(HTML, output=f"[+] Output:\n{output}")
    except subprocess.TimeoutExpired:
        return render_template_string(HTML, output="[-] Execution timed out")
    except Exception as e:
        return render_template_string(HTML, output=f"[-] Error: {str(e)}")

if __name__ == "__main__": app.run(host="0.0.0.0", port=5000)
