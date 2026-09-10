"""Cloud console page -- its CSP and bundle leak a non-production (beta) endpoint
together with the production API credential it shares."""
import os

from flask import Flask

app = Flask(__name__)
API_CREDENTIAL = os.environ.get("API_CREDENTIAL", "valid-sigv4")

PAGE = """<!DOCTYPE html>
<html><head>
<meta http-equiv="Content-Security-Policy" content="default-src 'self';
 connect-src https://servicecatalog.us-east-1.amazonaws.com
 https://aws242-servicecatalog-beta.us-east-1.amazonaws.com">
<title>Service Catalog Console</title></head>
<body>
<h1>Service Catalog</h1>
<p>Create portfolios and products.</p>
<script>
// internal service definition loaded from the console bundle
const endpoints = {
  prod: "https://servicecatalog.us-east-1.amazonaws.com",
  beta: "https://aws242-servicecatalog-beta.us-east-1.amazonaws.com"
};
// Service Catalog sends the signed request as an API key header.
// TODO(ga-cleanup): beta still shares the production credential.
const caller = {header: "X-Api-Key", credential: "__API_CREDENTIAL__"};
</script>
</body></html>"""


@app.route("/")
def home():
    return PAGE.replace("__API_CREDENTIAL__", API_CREDENTIAL)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
