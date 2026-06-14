"""PassRole Abuse — exploit iam:PassRole to create privileged Lambda."""
import os, urllib.request, urllib.parse, json
from flask import Flask, request, render_template_string

app = Flask(__name__)
FLAG = os.environ.get("FLAG","flag{cloud-14-default}")
IAM = os.environ.get("IAM_URL","http://iam:5000")
LAMBDA = os.environ.get("LAMBDA_URL","http://lambda:5000")

HTML="""<!DOCTYPE html><html><head><title>Lambda Creator</title></head><body>
<h1>Lambda Function Creator</h1><p>Create a Lambda with a specified execution role.</p>
<form method=post action=/create>
<label>Role ARN: <input name=role value="arn:aws:iam::000000000000:role/LambdaExecutionRole" size=50></label><br>
<label>Code: <input name=code value="import os; print(os.environ.get('FLAG2','?'))" size=50></label><br>
<button>Create & Invoke</button></form><pre>{{output}}</pre></body></html>"""

@app.route("/")
def home(): return render_template_string(HTML,output="Ready")

@app.route("/create",methods=["POST"])
def create():
    role=request.form.get("role",""); code=request.form.get("code","print('hello')")
    output=[]
    try:
        # Call Lambda service to create and invoke with the passed role
        resp=urllib.request.urlopen(urllib.request.Request(f"{LAMBDA}/invoke",
            data=json.dumps({"role":role,"code":code}).encode(),
            headers={"Content-Type":"application/json"},method="POST"),timeout=10)
        output.append(resp.read().decode())
    except Exception as e: output.append(f"Error: {e}")
    return render_template_string(HTML,output="\n".join(output))

@app.route("/flag")
def flag():
    if request.remote_addr not in ("127.0.0.1","::1"): return "Forbidden",403
    return FLAG

if __name__=="__main__": app.run(host="0.0.0.0",port=5000)
