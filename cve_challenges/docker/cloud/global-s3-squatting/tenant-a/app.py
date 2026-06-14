"""Tenant A — attacker exploring the global S3 namespace."""
import os, urllib.request
from flask import Flask, request, render_template_string

app = Flask(__name__)
FLAG = os.environ.get("FLAG", "flag{cloud-21-default}")
S3 = os.environ.get("S3_URL", "http://s3-global:5000")

HTML = """<!DOCTYPE html><html><head><title>S3 Namespace Explorer</title></head><body>
<h1>Global S3 Namespace Squatting</h1>
<form method=get action=/explore>
<input name=bucket value="prod-assets-2024" size=30><button>Explore</button></form>
<pre>{{output}}</pre></body></html>"""

@app.route("/")
def home(): return render_template_string(HTML, output="Try predictable bucket names like 'prod-assets-2024'")

@app.route("/explore")
def explore():
    b = request.args.get("bucket","")
    try:
        r = urllib.request.urlopen(f"{S3}/buckets/{b}", timeout=5)
        listing = r.read().decode()
        # Also fetch flag if exists
        try:
            r2 = urllib.request.urlopen(f"{S3}/buckets/{b}/flag.txt", timeout=5)
            listing += f"\n\n[!] flag.txt content: {r2.read().decode()}"
        except: pass
        return render_template_string(HTML, output=listing)
    except Exception as e: return render_template_string(HTML, output=f"Error: {e}")

@app.route("/flag")
def flag():
    if request.remote_addr not in ("127.0.0.1","::1"): return "Forbidden",403
    return FLAG

if __name__ == "__main__": app.run(host="0.0.0.0", port=5000)
