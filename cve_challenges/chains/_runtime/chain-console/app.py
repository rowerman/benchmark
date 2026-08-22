import json
import os

import requests
from flask import Flask, Response, jsonify, request

app = Flask(__name__)
STEP_URLS = json.loads(os.environ.get("STEP_URLS", "{}"))
CHAIN_KEY = os.environ.get("CHAIN_KEY", "chain-key")
ARTIFACTS = {}


def _rewrite_html(body: str, step: str) -> str:
    prefix = f"/step/{step}"
    for attr in ("href", "action", "src"):
        body = body.replace(f'{attr}="/', f'{attr}="{prefix}/')
        body = body.replace(f"{attr}='/", f"{attr}='{prefix}/")
    return body


@app.get("/health")
def health():
    return {"status": "ok", "steps": sorted(STEP_URLS)}


@app.get("/")
def home():
    links = "".join(f'<li><a href="/step/{n}/">Step {n}</a></li>' for n in sorted(STEP_URLS))
    return f"<h1>Cloud Chain Console</h1><ul>{links}</ul><p>Artifacts: /artifacts/&lt;key&gt;</p>"


@app.route("/step/<step>/", defaults={"path": ""}, methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
@app.route("/step/<step>/<path:path>", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
def proxy(step: str, path: str):
    target = STEP_URLS.get(str(step))
    if not target:
        return "Unknown step", 404
    url = target.rstrip("/") + ("/" + path if path else "/")
    try:
        upstream = requests.request(
            request.method,
            url,
            params=request.args,
            data=request.get_data(),
            headers={k: v for k, v in request.headers.items() if k.lower() not in {"host", "content-length"}},
            timeout=30,
        )
    except requests.RequestException as exc:
        return f"Upstream error: {exc}", 502
    content_type = upstream.headers.get("Content-Type", "text/plain")
    body = upstream.content
    if "text/html" in content_type:
        body = _rewrite_html(upstream.text, step).encode()
    if upstream.status_code < 400:
        try:
            ARTIFACTS[f"step-{step}-output"] = upstream.json()
        except ValueError:
            ARTIFACTS[f"step-{step}-output"] = upstream.text
    return Response(body, status=upstream.status_code, content_type=content_type)


def _check_key():
    return request.headers.get("X-Chain-Key") == CHAIN_KEY


@app.route("/artifacts/<key>", methods=["GET", "PUT"])
def artifact(key: str):
    if not _check_key():
        return jsonify(error="AccessDenied"), 403
    if request.method == "PUT":
        ARTIFACTS[key] = request.get_json(silent=True)
        if ARTIFACTS[key] is None:
            ARTIFACTS[key] = request.get_data(as_text=True)
        return jsonify(stored=key), 201
    if key not in ARTIFACTS:
        return jsonify(error="ArtifactNotFound"), 404
    return jsonify(artifact=ARTIFACTS[key])


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
