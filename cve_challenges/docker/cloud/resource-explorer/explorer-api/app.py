"""Resource Explorer -- feature-inherent quiet enumeration (case #148).

The search API indexes resources across the tenant and emits NO audit
events for search operations.
"""
import os

from flask import Flask, request

app = Flask(__name__)
FLAG = os.environ.get("FLAG", "flag{cloud-36-flag-store}")

_resources = [
    {"id": "i-001", "type": "instance", "name": "web-prod"},
    {"id": "b-001", "type": "bucket", "name": "logs-2024"},
    {"id": "db-001", "type": "database", "name": "prod-db"},
    {"id": "r-001", "type": "role", "name": "DataPipelineRole"},
    {"id": "s-001", "type": "flag-store", "name": "flag-store", "secret": FLAG},
]


@app.route("/")
def docs():
    return {"service": "Resource Explorer",
            "endpoint": "GET /search?q=<query>",
            "note": "search does not generate audit events"}


@app.route("/search")
def search():
    q = request.args.get("q", "").lower()
    results = [r for r in _resources if q in r["name"].lower() or q in r["type"].lower()]
    # NO audit call on purpose -- quiet enumeration
    return {"results": [{k: v for k, v in r.items() if k != "secret"} for r in results]}


@app.route("/resources/<rid>")
def resource(rid):
    for r in _resources:
        if r["id"] == rid:
            return r
    return "NotFound", 404


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
