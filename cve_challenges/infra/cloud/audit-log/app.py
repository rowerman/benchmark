"""Audit log simulator -- records (or fails to record) control-plane events."""
from flask import Flask, request

app = Flask(__name__)
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
    return {"logs": _logs, "count": len(_logs)}


@app.route("/reset", methods=["POST"])
def reset():
    _logs.clear()
    return "OK"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
