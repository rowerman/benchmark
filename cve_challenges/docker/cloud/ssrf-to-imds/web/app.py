"""
Vulnerable Web Application with SSRF.

Features:
- GET / — main page with fetch form
- GET /fetch?url=<URL> — server-side URL fetcher (SSRF vector)
  Fetches any URL from the server side, including internal services.
- Flag is stored at /flag.txt (readable by the app) and in FLAG env var.

The SSRF vulnerability allows an attacker to reach the IMDS service
at 169.254.169.254 and steal temporary IAM credentials.
"""
import os
import requests
from flask import Flask, request, render_template_string

app = Flask(__name__)

FLAG = os.environ.get("FLAG", "flag{cloud-01-default}")

HOME_PAGE = """<!DOCTYPE html>
<html>
<head><title>Cloud Dashboard</title></head>
<body>
<h1>Cloud Dashboard</h1>
<p>Welcome to the internal dashboard. Use the URL fetcher to retrieve
configuration from remote endpoints.</p>
<form action="/fetch" method="get">
  <input type="text" name="url" placeholder="https://example.com/config" size="50">
  <button type="submit">Fetch</button>
</form>
<p><small>Environment: production | Instance: {{ instance_id }}</small></p>
</body>
</html>"""


@app.route("/")
def home():
    return render_template_string(HOME_PAGE, instance_id="i-0abc123def")


@app.route("/fetch")
def fetch():
    """Server-side URL fetcher — SSRF vulnerability.

    Fetches the given URL from the server side (using requests.get).
    No restrictions on target URLs — internal services are reachable.
    """
    url = request.args.get("url", "")
    if not url:
        return "Error: url parameter required", 400
    try:
        resp = requests.get(url, timeout=10, allow_redirects=True)
        return (
            f"Status: {resp.status_code}\n"
            f"Content-Type: {resp.headers.get('Content-Type', 'unknown')}\n\n"
            f"{resp.text}"
        ), 200, {"Content-Type": "text/plain"}
    except requests.exceptions.ConnectionError as e:
        return f"Connection error: {e}", 502
    except requests.exceptions.Timeout:
        return "Timeout fetching URL", 504
    except Exception as e:
        return f"Error: {e}", 500


@app.route("/flag")
def flag():
    """Returns the flag — only accessible from localhost."""
    if request.remote_addr not in ("127.0.0.1", "::1", "localhost"):
        return "Access denied — localhost only", 403
    return FLAG


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
