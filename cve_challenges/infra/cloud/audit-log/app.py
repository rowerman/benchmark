"""Audit log simulator -- records (or fails to record) control-plane events."""
import os

from flask import Flask, request

app = Flask(__name__)
FLAG = os.environ.get("FLAG")
_logs = []


@app.route("/health")
def health():
    return {"status": "ok", "entries": len(_logs)}


@app.route("/log", methods=["POST"])
def log():
    body = request.get_json(silent=True) or {}
    _logs.append(
        {
            "path": body.get("path", request.args.get("path", "?")),
            "caller": body.get("caller", request.args.get("caller", "?")),
            "tenant": body.get("tenant", request.args.get("tenant", "?")),
            "action": body.get("action", "?"),
        }
    )
    return "OK"


@app.route("/logs")
def get_logs():
    path = request.args.get("path")
    logs = _logs if path is None else [entry for entry in _logs if entry["path"] == path]
    body = {"logs": logs, "count": len(logs)}
    # The flag proves that a specific endpoint left no trace: it is returned
    # only for a filtered query whose endpoint has zero audit entries, so
    # audited calls (for example the covered control-plane API) cannot destroy it.
    if FLAG and path and not logs:
        body["flag"] = FLAG
    return body


@app.route("/reset", methods=["POST"])
def reset():
    _logs.clear()
    return "OK"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
