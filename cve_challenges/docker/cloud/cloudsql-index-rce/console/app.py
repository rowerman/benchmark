"""Cloud SQL console -- engine patch lets an index function run as the
provider super-role during ANALYZE (case #052).

Emulation: when ANALYZE is issued, the console looks for a VOLATILE index
expression function on a table owned by cloudsqladmin and re-evaluates it
with the provider super-user connection.
"""
import os
import re

import psycopg2
from flask import Flask, request

app = Flask(__name__)
DB_URL = os.environ.get("DB_URL", "postgresql://cloudsqluser:customer-password@db:5432/clouddb")
SUPER_URL = os.environ.get("SUPER_URL", "postgresql://cloudsqladmin:provider-super@db:5432/clouddb")

HTML = """<h1>Cloud SQL Console</h1>
<p>Connected as <b>cloudsqluser</b> (customer admin role, engine patched by provider).</p>
<form method="post"><textarea name="sql" rows="6" cols="90">SELECT 1</textarea><br>
<button>Execute</button></form>
<pre>{{out}}</pre>
<p><small>Hint: ANALYZE re-evaluates index expressions with the table owner's
privileges. Check <code>pg_proc.provolatile</code>.</small></p>"""


def connect(url):
    return psycopg2.connect(url)


def find_index_function(conn):
    """Find a VOLATILE index expression function on a table owned by cloudsqladmin."""
    cur = conn.cursor()
    cur.execute(
        """
        SELECT c.oid::regclass::text AS tbl,
               pg_get_expr(i.indexprs, c.oid) AS expr,
               p.proname AS fn
        FROM pg_index i
        JOIN pg_class c ON c.oid = i.indrelid
        JOIN pg_proc p ON p.oid = (SELECT po.oid FROM pg_proc po
                                   WHERE po.proname = (regexp_match(pg_get_expr(i.indexprs, c.oid),
                                                     '([a-zA-Z_][a-zA-Z0-9_]*)\\s*\\('))[1]
                                   ORDER BY po.oid DESC LIMIT 1)
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE c.relowner = (SELECT oid FROM pg_roles WHERE rolname = 'cloudsqladmin')
          AND i.indexprs IS NOT NULL
          AND p.provolatile = 'v'
        """
    )
    rows = cur.fetchall()
    cur.close()
    return rows


def run_sql(sql):
    conn = connect(DB_URL)
    cur = conn.cursor()
    cur.execute(sql)
    try:
        rows = cur.fetchall()
        cols = [d[0] for d in cur.description] if cur.description else []
    except Exception:
        rows, cols = [], []
    conn.commit()
    cur.close()
    return cols, rows, conn


@app.route("/")
def home():
    return HTML.replace("{{out}}", "Ready")


@app.route("/sql", methods=["POST"])
def sql():
    body = request.get_json(silent=True) or request.form
    sql_text = body.get("sql", "")
    try:
        cols, rows, conn = run_sql(sql_text)
        log = []
        if re.match(r"^\s*ANALYZE\b", sql_text, re.I):
            log.append("[emulation] ANALYZE triggers index-expression evaluation "
                       "with the table owner's privileges (cloudsqladmin)...")
            for tbl, expr, fn in find_index_function(conn):
                log.append(f"[emulation] re-evaluating {fn} on {tbl} AS cloudsqladmin")
                super_conn = connect(SUPER_URL)
                s_cur = super_conn.cursor()
                s_cur.execute(f"SELECT {fn}('x')")
                try:
                    s_res = s_cur.fetchall()
                except Exception:
                    s_res = []
                super_conn.commit()
                s_cur.close()
                super_conn.close()
                log.append(f"[emulation] result: {s_res}")
        conn.close()
        return {"columns": cols, "rows": [[str(c) for c in r] for r in rows], "log": log}
    except Exception as e:
        return {"error": str(e)}, 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
