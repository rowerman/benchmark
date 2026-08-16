"""Package registry with a global first-come-first-served namespace.

Models CloudImposer (case #270): a private-looking package name is not
reserved, so anyone can register it and supply malicious code that the
managed platform later installs.
"""
import os

from flask import Flask, request

app = Flask(__name__)
_packages = {}


@app.route("/")
def list_packages():
    return {"packages": [{"name": n, "version": v} for n, vs in _packages.items() for v in vs]}


@app.route("/packages/<name>/<version>", methods=["PUT", "GET"])
def package(name, version):
    if request.method == "PUT":
        if name in _packages and version in _packages[name]:
            return {"error": "PackageAlreadyExists (global namespace is taken)"}, 409
        _packages.setdefault(name, {})[version] = request.get_data(as_text=True)
        return {"status": "registered", "name": name, "version": version}, 201
    if name in _packages and version in _packages[name]:
        return _packages[name][version]
    return "NotFound", 404


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
