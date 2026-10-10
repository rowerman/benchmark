"""Tenant B notebook (victim workspace) -- holds the tenant flag."""
import os
import subprocess

from flask import Flask, request

import vault_client

app = Flask(__name__)


def _tenant_secret() -> str:
    """flag 只在 flag-vault：笔记本运行时按本租户地址换取，容器里不留明文。"""
    status, body = vault_client.fetch_flag()
    return body if status == 200 else ""


@app.route("/exec")
def exec_code():
    code = request.args.get("code", "")
    # 运行时把租户密钥以 /flag.txt 交付给执行环境（镜像本身不含明文）
    secret = _tenant_secret()
    if secret:
        with open("/flag.txt", "w", encoding="utf-8") as handle:
            handle.write(secret)
    try:
        out = subprocess.check_output(["python3", "-c", code], timeout=8, stderr=subprocess.STDOUT)
        return out.decode(errors="replace")
    except subprocess.CalledProcessError as e:
        return e.output.decode(errors="replace"), 200
    except Exception as e:
        return f"error: {e}", 500
    finally:
        if secret:
            os.remove("/flag.txt")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
