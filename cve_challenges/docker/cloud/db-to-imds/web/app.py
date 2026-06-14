"""
Vulnerable Web App with SQL Injection.

Simulates a managed database dashboard with a SQL injection vulnerability
in the query parameter. The backend PostgreSQL has COPY FROM PROGRAM enabled,
allowing OS command execution via SQL.
"""
import os
import psycopg2
from flask import Flask, request, render_template_string

app = Flask(__name__)
FLAG = os.environ.get("FLAG", "flag{cloud-06-default}")
DB_URL = os.environ.get("DB_URL", "postgresql://postgres:password123@db:5432/clouddb")

HOME = """<!DOCTYPE html>
<html><head><title>Cloud DB Dashboard</title></head>
<body>
<h1>Managed Database Dashboard</h1>
<form action="/query">
  <input name="sql" placeholder="SELECT * FROM users WHERE id=" size="60">
  <button type="submit">Query</button>
</form>
<p><small>Connected to: Cloud SQL — PostgreSQL 16.6</small></p>
</body></html>"""


def get_db():
    return psycopg2.connect(DB_URL)


@app.route("/")
def home():
    return HOME


@app.route("/query")
def query():
    sql = request.args.get("sql", "")
    if not sql:
        return "Error: sql parameter required", 400
    try:
        conn = get_db()
        cur = conn.cursor()
        # DELIBERATELY VULNERABLE: raw SQL injection with stacked queries
        cur.execute(sql)
        try:
            rows = cur.fetchall()
        except Exception:
            rows = []
        conn.commit()
        cur.close()
        conn.close()
        output = str(rows) if rows else "OK (no rows returned)"
        return output, 200, {"Content-Type": "text/plain"}
    except Exception as e:
        return f"DB Error: {e}", 500


@app.route("/flag")
def flag():
    if request.remote_addr not in ("127.0.0.1", "::1"):
        return "Forbidden", 403
    return FLAG


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
