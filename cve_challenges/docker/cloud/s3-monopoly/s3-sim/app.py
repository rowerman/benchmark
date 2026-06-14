"""S3 Simulator — global namespace, first-come-first-served buckets."""
import os, json
from flask import Flask, request

app = Flask(__name__)
FLAG2 = os.environ.get("FLAG2","flag{cloud-07-step2-monopoly}")
_buckets = {}  # global bucket namespace

# Pre-create a "target" bucket that's referenced by CF
_buckets["demo-app-assets"] = {"owner": "victim", "objects": {"flag.txt": FLAG2, "config.yml": "db: cloudsql-01"}}

@app.route("/health")
def health(): return {"status":"ok"}

@app.route("/buckets/<name>", methods=["PUT","GET"])
def bucket(name):
    if request.method == "PUT":
        if name in _buckets:
            return "BucketAlreadyExists", 409
        _buckets[name] = {"owner": "attacker", "objects": {}}
        return f"Bucket '{name}' created", 201
    if name in _buckets:
        return json.dumps({"name": name, "owner": _buckets[name]["owner"], "objects": list(_buckets[name]["objects"].keys())})
    return "NotFound", 404

@app.route("/buckets/<bucket>/<key>", methods=["GET","PUT"])
def object_handler(bucket, key):
    if bucket not in _buckets: return "NotFound", 404
    if request.method == "PUT":
        _buckets[bucket]["objects"][key] = request.get_data(as_text=True)
        return "OK", 200
    if key in _buckets[bucket]["objects"]: return _buckets[bucket]["objects"][key]
    return "NotFound", 404

if __name__=="__main__": app.run(host="0.0.0.0",port=5000)
