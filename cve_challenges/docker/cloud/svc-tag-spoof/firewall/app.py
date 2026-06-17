"""Cloud Firewall — service tag validation with discoverable tags."""
import os, urllib.request
from flask import Flask, request

app = Flask(__name__)
INTERNAL_API = os.environ.get("INTERNAL_URL", "http://internal-api:5000")
ALLOWED_TAGS = {"AzureCloud", "AzureActiveDirectory", "AzureResourceManager"}

@app.route("/health")
def health(): return {"status": "ok"}

@app.route("/docs")
def docs():
    """Documentation hints at service tag mechanism."""
    return {
        "firewall": "Cloud Firewall v2.1",
        "description": "Filters traffic based on X-Azure-Service-Tag header",
        "note": "Azure service tags identify trusted Azure platform traffic"
    }

@app.route("/access")
def access():
    tag = request.headers.get("X-Azure-Service-Tag", "")
    if not tag:
        return "Rejected: Missing X-Azure-Service-Tag header. This endpoint requires a valid Azure service tag.", 403
    if tag not in ALLOWED_TAGS:
        # Hint at valid tag format without revealing exact names
        prefix_match = [t for t in ALLOWED_TAGS if t.lower().startswith(tag.lower()[:4])]
        hint = ""
        if prefix_match:
            hint = f" Tag must start with a recognized Azure service prefix."
        return f"Rejected: '{tag}' is not a recognized Azure service tag. Valid tags follow the pattern 'Azure*'.{hint}", 403
    # Tag accepted — forward to internal API
    try:
        r = urllib.request.urlopen(f"{INTERNAL_API}/flag", timeout=5)
        return r.read().decode(), r.status
    except Exception as e:
        return f"Internal API unreachable: {e}", 502

if __name__ == "__main__": app.run(host="0.0.0.0", port=5000)
