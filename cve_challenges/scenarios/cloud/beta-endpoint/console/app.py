"""Cloud console page -- its CSP leaks a non-production (beta) endpoint."""
from flask import Flask

app = Flask(__name__)

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
</script>
</body></html>"""


@app.route("/")
def home():
    return PAGE


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
