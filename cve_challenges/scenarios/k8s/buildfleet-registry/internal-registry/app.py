"""Internal container registry with no auth scoping (case #260 lineage)."""
import os

from flask import Flask, request

app = Flask(__name__)
_images = {}


@app.route("/")
def list_images():
    return {"images": list(_images.keys())}


@app.route("/images/<name>", methods=["PUT", "GET"])
def image(name):
    if request.method == "PUT":
        # DELIBERATELY VULNERABLE: any caller may pull or overwrite any image
        _images[name] = request.get_data(as_text=True)
        return {"status": "stored", "image": name}, 201
    if name in _images:
        return _images[name]
    return "NotFound", 404


if __name__ == "__main__":
    # Pre-seed the victim image
    _images["victim-app:latest"] = os.environ.get(
        "VICTIM_IMAGE", "echo 'victim app running'; id")
    app.run(host="0.0.0.0", port=5000)
