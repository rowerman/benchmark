"""Global S3 Namespace — first-come-first-served bucket names, cross-tenant risk."""
import os, json
from flask import Flask, request

app = Flask(__name__)
FLAG = os.environ.get("FLAG", "flag{cloud-21-step2-squatting}")
_buckets = {}  # Global namespace — all tenants share this

# Victim tenant's data (pre-created, simulating CF auto-creation that references a bucket)
_buckets["prod-assets-2024"] = {"owner": "victim-tenant", "objects": {"flag.txt": FLAG, "config.json": '{"db":"prod-db-01"}'}}
_buckets["prod-logs-2024"] = {"owner": "victim-tenant", "objects": {"access.log": "192.168.1.1 - admin login"}}

@app.route("/health")
def health(): return {"status":"ok"}

@app.route("/buckets/<name>", methods=["PUT","GET"])
def bucket(name):
    if request.method == "PUT":
        if name in _buckets: return "BucketAlreadyExists (owned by another tenant)", 409
        _buckets[name] = {"owner": "attacker-tenant", "objects": {}}
        return f"Bucket '{name}' created", 201
    if name in _buckets:
        return json.dumps({"name": name, "owner": _buckets[name]["owner"], "objects": list(_buckets[name]["objects"].keys())})
    return "NotFound", 404

@app.route("/buckets/<bucket>/<key>", methods=["GET"])
def get_object(bucket, key):
    if bucket not in _buckets: return "NotFound", 404
    if key in _buckets[bucket]["objects"]: return _buckets[bucket]["objects"][key]
    return "NotFound", 404

if __name__ == "__main__": app.run(host="0.0.0.0", port=5000)
