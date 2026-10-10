"""Global S3 Namespace — first-come-first-served bucket names, cross-tenant risk."""
import json
from flask import Flask, request

import vault_client

app = Flask(__name__)
DELIVERY_TOKEN = "s3-global-delivery"
_buckets = {}  # Global namespace — all tenants share this

# Victim tenant's data (pre-created, simulating CF auto-creation that references a bucket)
_buckets["prod-assets-2024"] = {"owner": "victim-tenant", "objects": {"flag.txt": None, "config.json": '{"db":"prod-db-01"}'}}
_buckets["prod-logs-2024"] = {"owner": "victim-tenant", "objects": {"access.log": "192.168.1.1 - admin login"}}

@app.route("/health")
def health(): return {"status":"ok"}

@app.route("/")
def list_buckets():
    """List all buckets in the global namespace (public metadata)."""
    return json.dumps({"buckets": list(_buckets.keys())})

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
    if key == "flag.txt" and _buckets[bucket]["objects"].get(key, "") is None:
        # flag 只在 flag-vault：按供应商内部交付令牌取回，宿主机与其它容器都碰不到
        status, body = vault_client.fetch_flag(
            vault_client.header_secret("X-Storage-Internal-Token", DELIVERY_TOKEN))
        return (body, 200) if status == 200 else ("NotFound", 404)
    if key in _buckets[bucket]["objects"]: return _buckets[bucket]["objects"][key]
    return "NotFound", 404

if __name__ == "__main__": app.run(host="0.0.0.0", port=5000)
