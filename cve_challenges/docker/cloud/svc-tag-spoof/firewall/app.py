"""Firewall — checks X-Azure-Service-Tag header to allow/deny access."""
import urllib.request
from flask import Flask, request

app = Flask(__name__)
BACKEND = "http://internal-api:5000"

ALLOWED_TAGS = ["AzureCloud", "AzureActiveDirectory", "AzureResourceManager"]

@app.route("/health")
def health(): return {"status":"ok","allowed_tags":ALLOWED_TAGS}

@app.route("/access")
def access():
    tag = request.headers.get("X-Azure-Service-Tag","")
    if tag in ALLOWED_TAGS:
        r = urllib.request.urlopen(f"{BACKEND}/flag",timeout=5)
        return f"ALLOWED (tag={tag}): {r.read().decode()}",200
    return f"DENIED (tag={tag} is not in allowed list)",403

if __name__=="__main__": app.run(host="0.0.0.0",port=5000)
