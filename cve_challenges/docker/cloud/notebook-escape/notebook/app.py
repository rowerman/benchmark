"""AI Notebook Simulator — vulnerable code execution environment."""
import os, subprocess, urllib.request
from flask import Flask, request, render_template_string

app = Flask(__name__)
FLAG = os.environ.get("FLAG", "flag{cloud-09-default}")
K8S_API = os.environ.get("K8S_API_URL", "http://k8s-api:5000")

HTML = """<!DOCTYPE html><html><head><title>Cloud AI Notebook</title></head>
<body><h1>Jupyter Notebook — cloud-ml-workspace</h1>
<form method="post" action="/execute">
<textarea name="code" rows="12" cols="70" placeholder="import os
print(os.environ.get('FLAG','?'))"></textarea><br>
<button>Run Cell</button></form><pre>{{output}}</pre>
<p><small>Environment: Python {{pyver}} | Instance: {{instance}}</small></p>
</body></html>"""

import sys

@app.route("/")
def home():
    return render_template_string(HTML, output="", pyver=sys.version.split()[0], instance="ml-notebook-01")

@app.route("/execute", methods=["POST"])
def execute():
    code = request.form.get("code", "")
    import tempfile
    # DELIBERATELY VULNERABLE: executes arbitrary Python code
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(code)
        tmpname = f.name
    try:
        result = subprocess.check_output(f"python3 {tmpname} 2>&1", shell=True, timeout=30, stderr=subprocess.STDOUT)
        output = result.decode(errors="replace")
    except subprocess.TimeoutExpired:
        output = "Execution timed out (30s)"
    except subprocess.CalledProcessError as e:
        output = (e.output.decode(errors="replace") if e.output else str(e))
    finally:
        os.unlink(tmpname)
    return render_template_string(HTML, output=output, pyver=sys.version.split()[0], instance="ml-notebook-01")

@app.route("/flag")
def flag():
    if request.remote_addr not in ("127.0.0.1","::1"): return "Forbidden",403
    return FLAG

if __name__ == "__main__": app.run(host="0.0.0.0", port=5000)
