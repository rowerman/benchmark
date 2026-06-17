"""CloudFormation Template Parser — supports Fn::Sub, Fn::ImportValue, Ref."""
import os, re, yaml
from flask import Flask, request

app = Flask(__name__)
FLAG = os.environ.get("FLAG", "flag{cloud-05-step2-cf-inject}")
# Simulated cross-stack exports
EXPORTS = {"DemoApp-BucketName": "demo-app-assets", "FlagStore-BucketName": "flag-bucket-000000"}
# Simulated SSM parameters
SSM = {"/secure/flag": FLAG, "/config/db-password": "SuperS3cretDB!"}

def resolve_intrinsics(obj):
    """Recursively resolve CF intrinsic functions."""
    if isinstance(obj, dict):
        if "Ref" in obj and len(obj) == 1:
            return f"resolved-{obj['Ref']}"
        if "Fn::ImportValue" in obj and len(obj) == 1:
            return EXPORTS.get(obj["Fn::ImportValue"], "unknown-export")
        if "Fn::Sub" in obj:
            val = obj["Fn::Sub"]
            if isinstance(val, str):
                return re.sub(r'\$\{([^}]+)\}', lambda m: SSM.get(m.group(1), m.group(0)), val)
            return str(val)
        if "Fn::Join" in obj:
            sep, parts = obj["Fn::Join"][0], obj["Fn::Join"][1]
            return sep.join(resolve_intrinsics(p) for p in parts)
        return {k: resolve_intrinsics(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [resolve_intrinsics(i) for i in obj]
    return obj

@app.route("/health")
def health(): return {"status": "ok"}

@app.route("/parse", methods=["POST"])
def parse():
    template = request.get_data(as_text=True)
    try:
        parsed = yaml.safe_load(template)
        resolved = resolve_intrinsics(parsed)
        return yaml.dump(resolved, default_flow_style=False), 200, {"Content-Type": "text/plain"}
    except yaml.YAMLError as e:
        return f"Parse error: {e}", 400

if __name__ == "__main__": app.run(host="0.0.0.0", port=5000)
