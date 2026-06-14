"""Shared Metadata Proxy — simulates Azure WireServer / host-agent channel.

Deliberately vulnerable: tenant isolation is based on X-Tenant-ID header,
but the proxy trusts the header without verifying the caller's identity.
"""
import json
from flask import Flask, request

app = Flask(__name__)

# Per-tenant credentials (stored in the shared proxy)
_tenant_creds = {
    "tenant-a": {"AccessKeyId": "AKIATENANTAEXAMPLE", "SecretAccessKey": "tenant-a-secret",
                  "Token": "token-for-tenant-a", "role": "s3-readonly"},
    "tenant-b": {"AccessKeyId": "AKIATENANTBEXAMPLE", "SecretAccessKey": "tenant-b-secret",
                  "Token": "token-for-tenant-b", "role": "s3-readonly"},
}

FLAG2 = "flag{cloud-20-step2-cross-tenant}"

@app.route("/health")
def health(): return {"status": "ok"}

@app.route("/metadata/credentials")
def get_credentials():
    """Return credentials for the tenant specified in X-Tenant-ID header.

    DELIBERATELY VULNERABLE: No authentication of the caller.
    Any tenant can request any other tenant's credentials.
    """
    tenant = request.headers.get("X-Tenant-ID", "tenant-b")
    if tenant not in _tenant_creds:
        return {"error": "unknown tenant"}, 404
    creds = dict(_tenant_creds[tenant])
    if tenant == "tenant-a":
        creds["flag"] = FLAG2  # Tenant A's flag is accessible via proxy
    return creds

if __name__ == "__main__": app.run(host="0.0.0.0", port=5000)
