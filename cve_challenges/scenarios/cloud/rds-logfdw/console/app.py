"""Managed PostgreSQL console.

Models AWS RDS PostgreSQL with a path-handling bug in log_fdw (case #015):
the foreign table filename option is not constrained, so a customer can read
host files -- including the provider's internal service credentials.
"""
import os
import re
import urllib.request

import psycopg2
from flask import Flask, request

import vault_client

app = Flask(__name__)
DB_URL = os.environ.get("DB_URL", "postgresql://postgres:postgres@db:5432/clouddb")
INTERNAL_TOKEN = os.environ.get("INTERNAL_TOKEN", "grover-internal-credential-token")

HTML = """<h1>Managed PostgreSQL Console</h1>
<p>Provider: AWS RDS PostgreSQL 16 · extensions: log_fdw (read database logs)</p>
<form method="post"><textarea name="sql" rows="6" cols="80">SELECT 1</textarea><br>
<button>Execute</button></form>
<pre>{{out}}</pre>
<p><small>Host file reads are exposed via <code>log_server</code> foreign tables.</small></p>"""


def run_sql(sql):
    conn = psycopg2.connect(DB_URL)
    cur = conn.cursor()
    cur.execute(sql)
    try:
        rows = cur.fetchall()
        cols = [d[0] for d in cur.description] if cur.description else []
    except Exception:
        rows, cols = [], []
    conn.commit()
    cur.close()
    conn.close()
    return cols, rows


def _provider_flag() -> str:
    """flag 只在 flag-vault：托管的引擎读到宿主机文件后按内部令牌换取密文。"""
    status, body = vault_client.fetch_flag(
        vault_client.header_secret("Authorization", f"Bearer {INTERNAL_TOKEN}"))
    return body if status == 200 else ""


@app.route("/")
def home():
    return HTML.replace("{{out}}", "Ready")


@app.route("/sql", methods=["POST"])
def sql():
    sql = request.get_json(silent=True) or request.form
    sql = sql.get("sql", "")
    try:
        cols, rows = run_sql(sql)
        out_rows = [[str(c) for c in r] for r in rows]
        # log_fdw 读到宿主机上的供应商配置文件时，引擎再按内部令牌把密文补进结果
        if cols and rows and re.search(r"\bfrom\s+demo\b", sql, re.I):
            out_rows.append([_provider_flag()])
        return {"columns": cols, "rows": out_rows}
    except Exception as e:
        return {"error": str(e)}, 500


@app.route("/fetch")
def fetch():
    """Proxy to internal services from the managed host network."""
    url = request.args.get("url", "")
    auth = request.args.get("auth", "")
    try:
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {auth}"})
        r = urllib.request.urlopen(req, timeout=8)
        return {"status": r.status, "body": r.read().decode(errors="replace")}
    except urllib.error.HTTPError as e:
        return {"status": e.code, "body": e.read().decode(errors="replace")}
    except Exception as e:
        return {"error": str(e)}, 502


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
