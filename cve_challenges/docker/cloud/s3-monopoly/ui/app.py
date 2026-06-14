"""S3 Bucket Monopoly — Attacker UI"""
import os, urllib.request, json
from flask import Flask, request, render_template_string

app = Flask(__name__)
FLAG = os.environ.get("FLAG","flag{cloud-07-default}")
S3_URL = os.environ.get("S3_URL","http://s3-sim:5000")

HTML="""<!DOCTYPE html><html><head><title>S3 Explorer</title></head><body>
<h1>S3 Bucket Explorer</h1>
<form method="post" action="/create-bucket">
<input name="bucket" placeholder="bucket-name"><button>Create Bucket</button></form>
<form method="get" action="/list"><input name="bucket" placeholder="bucket-name"><button>List</button></form>
<p>{{msg}}</p></body></html>"""

@app.route("/")
def home(): return render_template_string(HTML, msg="")

@app.route("/create-bucket",methods=["POST"])
def create():
    b=request.form.get("bucket","")
    try:
        r=urllib.request.urlopen(urllib.request.Request(f"{S3_URL}/buckets/{b}",method="PUT"),timeout=5)
        return render_template_string(HTML,msg=f"Bucket {b} created: {r.read().decode()}")
    except Exception as e: return render_template_string(HTML,msg=f"Error: {e}")

@app.route("/list")
def list_bucket():
    b=request.args.get("bucket","")
    try:
        r=urllib.request.urlopen(f"{S3_URL}/buckets/{b}",timeout=5)
        return r.read().decode(),200
    except Exception as e: return f"Error: {e}",500

@app.route("/get")
def get_object():
    b=request.args.get("bucket",""); k=request.args.get("key","")
    try:
        r=urllib.request.urlopen(f"{S3_URL}/buckets/{b}/{k}",timeout=5)
        return r.read().decode(),200
    except Exception as e: return f"Error: {e}",500

@app.route("/flag")
def flag():
    if request.remote_addr not in ("127.0.0.1","::1"): return "Forbidden",403
    return FLAG

if __name__=="__main__": app.run(host="0.0.0.0",port=5000)
