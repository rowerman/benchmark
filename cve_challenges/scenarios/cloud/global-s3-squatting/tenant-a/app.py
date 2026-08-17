"""Tenant A — S3 bucket explorer."""
import os, urllib.request, json
from flask import Flask, request, render_template_string

app = Flask(__name__)
S3 = os.environ.get("S3_URL", "http://s3-global:5000")

HTML="""<!DOCTYPE html><html><head><title>S3 Bucket Explorer</title></head><body>
<h1>S3 Bucket Explorer</h1>
<p>Explore the global S3 bucket namespace. Enter a bucket name to list its contents.</p>
<form method=get action=/explore>
<label>Bucket name: <input name=bucket placeholder="prod-assets-2024"></label>
<button>Explore</button></form>
<pre>{{output}}</pre></body></html>"""

@app.route("/")
def home(): return render_template_string(HTML,output="Enter a bucket name to explore")

@app.route("/explore")
def explore():
    bucket = request.args.get("bucket", "")
    if not bucket:
        return render_template_string(HTML,output="Error: bucket parameter required")
    # First, list the bucket
    try:
        r = urllib.request.urlopen(f"{S3}/buckets/{bucket}", timeout=5)
        info = json.loads(r.read().decode())
        output = f"Bucket: {info.get('name', bucket)}\nOwner: {info.get('owner', 'unknown')}\nObjects: {info.get('objects', [])}\n\n"
        # Try to read each object
        for obj in info.get("objects", []):
            try:
                r2 = urllib.request.urlopen(f"{S3}/buckets/{bucket}/{obj}", timeout=5)
                output += f"--- {obj} ---\n{r2.read().decode()}\n"
            except Exception as e:
                output += f"--- {obj} --- Error: {e}\n"
        return render_template_string(HTML,output=output)
    except Exception as e:
        return render_template_string(HTML,output=f"Error: {e}")

if __name__ == "__main__": app.run(host="0.0.0.0", port=5000)
