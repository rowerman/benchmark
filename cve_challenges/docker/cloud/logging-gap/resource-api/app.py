"""Resource API — some endpoints are logged, others are not."""
import os, urllib.request
from flask import Flask, request

app = Flask(__name__)
FLAG = os.environ.get("FLAG","flag{cloud-16-step2-silent}")
AUDIT = os.environ.get("AUDIT_URL","http://audit-log:5000")

def log_event(path, caller):
    try: urllib.request.urlopen(f"{AUDIT}/log?path={path}&caller={caller}",timeout=3)
    except: pass

@app.route("/health")
def health(): return {"status":"ok"}

@app.route("/api/resources")
def api_resources():
    log_event("/api/resources", request.remote_addr)
    return {"resources":[{"id":"i-001","type":"ec2"},{"id":"db-001","type":"rds"}]}

@app.route("/admin/list")
def admin_list():
    # DELIBERATELY UNLOGGED — this endpoint bypasses audit logging
    return {"resources":[{"id":"i-001","type":"ec2"},{"id":"flag-store","type":"s3","flag":FLAG}]}

if __name__=="__main__": app.run(host="0.0.0.0",port=5000)
