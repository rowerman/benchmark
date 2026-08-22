import os

from flask import Flask, request

app = Flask(__name__)
FLAG = os.environ.get("FLAG", "flag{cloud-06-pipeline}")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/protected-artifact")
def protected_artifact():
    if request.headers.get("X-Workload-Token") != "ci-workload-token":
        return {"error": "AccessDenied"}, 403
    return {"role": "arn:aws:iam::111122223333:role/ci-build",
            "artifact": "release-manifest", "flag": FLAG}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
