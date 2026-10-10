"""Audit log simulator -- records (or fails to record) control-plane events."""
import os

from flask import Flask, request

try:
    import vault_client
except ImportError:
    # 只有把 flag 迁到 flag-vault 的场景才挂载这个客户端
    vault_client = None

app = Flask(__name__)
_logs = []


def _flag() -> str:
    """flag 只在 flag-vault：本服务以内部地址身份换取，容器里不留明文。"""
    fallback = os.environ.get("FLAG", "")
    if vault_client is None:
        return fallback
    status, body = vault_client.fetch_flag()
    return body if status == 200 else fallback


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
    if path and not logs:
        flag = _flag()
        if flag:
            body["flag"] = flag
    return body


@app.route("/reset", methods=["POST"])
def reset():
    _logs.clear()
    return "OK"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
