"""CloudFormation Console — accepts YAML templates for stack creation."""
import os, urllib.request, json
from flask import Flask, request, render_template_string

app = Flask(__name__)
FLAG = os.environ.get("FLAG", "flag{cloud-05-default}")
PARSER_URL = os.environ.get("PARSER_URL", "http://parser:5000/parse")

HTML = """<!DOCTYPE html>
<html><head><title>CloudFormation Console</title></head>
<body>
<h1>CloudFormation Stack Creator</h1>
<form method="post" action="/create">
<textarea name="template" rows="15" cols="60" placeholder="AWSTemplateFormatVersion: '2010-09-09'
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: my-app-assets"></textarea><br>
<button type="submit">Create Stack</button>
</form>
<p>Supports: Fn::Sub, Fn::ImportValue, Ref</p>
</body></html>"""

@app.route("/")
def home(): return HTML

@app.route("/create", methods=["POST"])
def create():
    template = request.form.get("template", "")
    try:
        req = urllib.request.Request(PARSER_URL, data=template.encode(),
            headers={"Content-Type": "text/plain"}, method="POST")
        r = urllib.request.urlopen(req, timeout=10)
        return r.read().decode(), r.status
    except Exception as e:
        return f"Error: {e}", 500

@app.route("/flag")
def flag():
    if request.remote_addr not in ("127.0.0.1","::1"): return "Forbidden",403
    return FLAG

if __name__ == "__main__": app.run(host="0.0.0.0", port=5000)
