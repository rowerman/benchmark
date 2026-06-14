"""Audit Log Simulator — records API calls (some endpoints bypass logging)."""
from flask import Flask, request

app = Flask(__name__)
_logs = []

@app.route("/health")
def health(): return {"status":"ok","entries":len(_logs)}

@app.route("/log")
def log():
    path = request.args.get("path","?"); caller = request.args.get("caller","?")
    _logs.append({"path":path,"caller":caller})
    return "OK"

@app.route("/logs")
def get_logs(): return {"logs":_logs}

if __name__=="__main__": app.run(host="0.0.0.0",port=5000)
