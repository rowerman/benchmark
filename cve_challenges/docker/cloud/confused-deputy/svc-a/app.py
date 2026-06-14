"""Service A — Deputy. Forwards requests to other services with its managed identity."""
import urllib.request
from flask import Flask, request

app = Flask(__name__)
# Managed Identity token
MI_TOKEN = "Bearer mi-token-svc-a-identity"

@app.route("/health")
def health(): return {"status":"ok"}

@app.route("/proxy")
def proxy():
    target = request.args.get("to","")
    if not target: return "Missing target",400
    # DELIBERATELY VULNERABLE: forwards to any target with its managed identity
    try:
        r = urllib.request.urlopen(urllib.request.Request(f"http://{target}/data",
            headers={"Authorization": MI_TOKEN}), timeout=5)
        return r.read().decode(), r.status
    except Exception as e: return f"Proxy error: {e}",502

if __name__=="__main__": app.run(host="0.0.0.0",port=5000)
