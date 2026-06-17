"""Shared AI Inference Queue — multi-tenant, weak tenant isolation."""
import os, json
from flask import Flask, request

app = Flask(__name__)
FLAG = os.environ.get("FLAG", "flag{cloud-22-step2-inference}")

# Shared inference queue — all tenants share this
_queue = []
_results = {}  # job_id → result

# Pre-populate with a victim tenant's job that includes sensitive data
_queue.append({"job_id": "job-001", "tenant": "victim", "model": "classifier",
               "input_data": f"Sensitive: credit_card=4111-1111-1111-1111, flag={FLAG}"})

@app.route("/health")
def health(): return {"status":"ok"}

@app.route("/queue", methods=["GET", "POST"])
def queue():
    if request.method == "POST":
        body = request.get_json(silent=True) or {}
        job = {"job_id": f"job-{len(_queue)+1:03d}",
               "tenant": body.get("tenant", "unknown"),
               "model": body.get("model", ""),
               "input_data": body.get("input_data", "")}
        _queue.append(job)
        return {"status": "queued", "job_id": job["job_id"]}
    # DELIBERATELY VULNERABLE: returns ALL jobs, regardless of tenant
    return {"queue": _queue}

@app.route("/results/<job_id>")
def get_result(job_id):
    if job_id in _results: return _results[job_id]
    # Fallback: check queue for job data (cross-tenant leak)
    for job in _queue:
        if job["job_id"] == job_id:
            return {"job": job, "status": "pending"}
    return {"error": "not found"}, 404

if __name__ == "__main__": app.run(host="0.0.0.0", port=5000)
