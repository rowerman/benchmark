"""CloudFormation Console — accepts YAML templates, shows available exports."""
import os, urllib.request, json
from flask import Flask, request, render_template_string

app = Flask(__name__)
PARSER = os.environ.get("PARSER_URL", "http://parser:5000")

# Available CloudFormation exports — hints at SSM parameter naming convention
EXPORTS = {
    "AppDatabasePassword": "/secure/app/db-password",
    "AppApiKey": "/secure/app/api-key",
    "LogBucketName": "logs-bucket-2024",
    "CacheEndpoint": "redis-cluster.prod.internal",
}

HTML="""<!DOCTYPE html><html><head><title>CloudFormation Console</title></head><body>
<h1>CloudFormation Stack Creator</h1>
<h3>Available Exports (use Fn::ImportValue or Fn::Sub to reference)</h3>
<pre>{{exports}}</pre>
<p>Supports: Ref, Fn::Sub, Fn::ImportValue, Fn::Join</p>
<form method=post action=/create>
<textarea name=template rows=12 cols=70 placeholder="AWSTemplateFormatVersion: '2010-09-09'
Resources:
  MyResource:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !Sub ${/secure/flag}"></textarea><br>
<button>Create Stack</button></form>
<pre>{{output}}</pre></body></html>"""

@app.route("/")
def home():
    exports_display = "\n".join([f"  {k} → {v}" for k, v in EXPORTS.items()])
    return render_template_string(HTML, exports=exports_display, output="Ready — paste a CloudFormation template above")

@app.route("/create", methods=["POST"])
def create():
    template = request.form.get("template", "")
    if not template:
        return render_template_string(HTML, exports="", output="Error: template required")
    try:
        req = urllib.request.Request(f"{PARSER}/parse",
            data=json.dumps({"template": template}).encode(),
            headers={"Content-Type": "application/json"})
        r = urllib.request.urlopen(req, timeout=10)
        return render_template_string(HTML, exports="", output=f"Stack created:\n{r.read().decode()}")
    except Exception as e:
        return render_template_string(HTML, exports="", output=f"Error: {e}")

if __name__ == "__main__": app.run(host="0.0.0.0", port=5000)
