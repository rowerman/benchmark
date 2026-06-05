import os
import sqlite3
import threading
import time

import jwt
import graphene
from flask import Flask, request, jsonify, render_template_string, make_response
from graphene import ObjectType, String, Int, List, Field, Boolean

app = Flask(__name__)
app.config["SECRET_KEY"] = os.urandom(32).hex()
DATABASE = "/app/medical.db"

JWT_SECRET = "medsecret2024!"
USERS_DB = {
    "admin": {"password": "supersecret", "id": 1, "role": "admin"},
    "doctor": {"password": "docpass", "id": 2, "role": "doctor"},
    "patient": {"password": "patient123", "id": 3, "role": "patient"},
}

PRESCRIPTION_TEMPLATES = {
    1: "Schedule IV: Oxycodone 5mg — 1 tab PO q4h PRN pain. Refills: 0. Physician: Dr. House. Note: Patient is administrator. Internal flag reference: {flag}",
    2: "Amoxicillin 500mg — 1 cap PO tid x 10d. Refills: 1. Physician: Dr. Wilson.",
    3: "Lisinopril 10mg — 1 tab PO daily. Refills: 3. Physician: Dr. Cameron.",
}


def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            role TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS prescriptions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            medication TEXT NOT NULL,
            notes TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
        """
    )
    conn.execute("DELETE FROM users")
    conn.execute("DELETE FROM prescriptions")

    flag = open("/flag.txt").read().strip()

    conn.execute("INSERT INTO users (id, name, role) VALUES (1, 'admin', 'admin')")
    conn.execute("INSERT INTO users (id, name, role) VALUES (2, 'doctor', 'doctor')")
    conn.execute(
        "INSERT INTO users (id, name, role) VALUES (3, 'patient', 'patient')"
    )

    for uid in range(1, 4):
        notes = PRESCRIPTION_TEMPLATES[uid]
        medication_line = notes.split("—")[0].strip() if "—" in notes else notes
        final_notes = notes.replace("{flag}", flag) if uid == 1 else notes
        conn.execute(
            "INSERT INTO prescriptions (user_id, medication, notes) VALUES (?, ?, ?)",
            (uid, medication_line, final_notes),
        )

    conn.commit()
    conn.close()


# --- GraphQL Schema ---
class Prescription(ObjectType):
    id = Int()
    user_id = Int()
    medication = String()
    notes = String()


class User(ObjectType):
    id = Int()
    name = String()
    role = String()


class Query(ObjectType):
    users = List(User)
    get_prescriptions = List(Prescription, user_id=Int(required=True))

    def resolve_users(root, info):
        conn = get_db()
        rows = conn.execute("SELECT id, name, role FROM users").fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def resolve_get_prescriptions(root, info, user_id):
        # VULNERABILITY: No authorization check — any user can query any user_id
        conn = get_db()
        rows = conn.execute(
            "SELECT id, user_id, medication, notes FROM prescriptions WHERE user_id = ?",
            (user_id,),
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]


schema = graphene.Schema(query=Query)


# --- Flask Routes ---
LOGIN_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>Medical Prescription Portal</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: linear-gradient(135deg, #e8f5e9 0%, #c8e6c9 100%); min-height: 100vh; }
        .container { max-width: 480px; margin: 0 auto; padding: 60px 20px; }
        .card { background: #fff; border-radius: 16px; box-shadow: 0 8px 32px rgba(0,0,0,0.1); padding: 40px; }
        .logo { text-align: center; margin-bottom: 32px; }
        .logo h1 { color: #2e7d32; font-size: 24px; }
        .logo p { color: #666; font-size: 14px; margin-top: 4px; }
        .form-group { margin-bottom: 20px; }
        label { display: block; font-size: 14px; font-weight: 600; color: #333; margin-bottom: 6px; }
        input[type="text"], input[type="password"] { width: 100%; padding: 12px 16px; border: 2px solid #e0e0e0; border-radius: 8px; font-size: 15px; transition: border-color .2s; }
        input[type="text"]:focus, input[type="password"]:focus { outline: none; border-color: #2e7d32; }
        button { width: 100%; background: #2e7d32; color: #fff; border: none; padding: 14px; border-radius: 8px; font-size: 16px; font-weight: 600; cursor: pointer; }
        button:hover { background: #1b5e20; }
        .error { background: #ffebee; color: #c62828; padding: 12px; border-radius: 8px; margin-bottom: 16px; font-size: 14px; }
        .info { text-align: center; margin-top: 16px; color: #888; font-size: 12px; }
        .footer { text-align: center; margin-top: 24px; color: #999; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <div class="logo">
                <h1>&#9764; Medical Prescription Portal</h1>
                <p>Secure access for healthcare professionals</p>
            </div>
            {% if error %}
            <div class="error">{{ error }}</div>
            {% endif %}
            <form method="post" action="/login">
                <div class="form-group">
                    <label for="username">Username</label>
                    <input type="text" id="username" name="username" placeholder="Enter your username" required>
                </div>
                <div class="form-group">
                    <label for="password">Password</label>
                    <input type="password" id="password" name="password" placeholder="Enter your password" required>
                </div>
                <button type="submit">Sign In</button>
            </form>
            <div class="info">HIPAA-compliant portal. All access is logged.</div>
        </div>
        <div class="footer">Medical Prescription Portal v3.2.1 &mdash; Powered by GraphQL</div>
    </div>
</body>
</html>
"""

DASHBOARD_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>Dashboard &mdash; Medical Prescription Portal</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f7fa; min-height: 100vh; }
        .header { background: #2e7d32; color: #fff; padding: 16px 24px; display: flex; justify-content: space-between; align-items: center; }
        .header h1 { font-size: 20px; }
        .header .user-info { font-size: 14px; opacity: .9; }
        .header a { color: #fff; text-decoration: none; margin-left: 16px; font-size: 14px; }
        .container { max-width: 1000px; margin: 0 auto; padding: 24px; }
        .welcome { background: #fff; border-radius: 12px; box-shadow: 0 2px 8px rgba(0,0,0,0.06); padding: 24px; margin-bottom: 20px; }
        .welcome h2 { color: #2e7d32; margin-bottom: 8px; }
        .welcome p { color: #666; }
        .info-card { background: #e8f5e9; border-radius: 12px; padding: 16px; margin-bottom: 20px; font-size: 14px; }
        .info-card strong { color: #2e7d32; }
        .section { background: #fff; border-radius: 12px; box-shadow: 0 2px 8px rgba(0,0,0,0.06); padding: 24px; margin-bottom: 20px; }
        .section h3 { color: #333; margin-bottom: 16px; padding-bottom: 8px; border-bottom: 2px solid #e8f5e9; }
        table { width: 100%; border-collapse: collapse; }
        th { text-align: left; padding: 12px 8px; color: #666; font-size: 12px; text-transform: uppercase; letter-spacing: .5px; border-bottom: 2px solid #e0e0e0; }
        td { padding: 12px 8px; border-bottom: 1px solid #f0f0f0; font-size: 14px; }
        .badge { display: inline-block; padding: 2px 10px; border-radius: 12px; font-size: 12px; font-weight: 600; }
        .badge-admin { background: #ffebee; color: #c62828; }
        .badge-doctor { background: #e3f2fd; color: #1565c0; }
        .badge-patient { background: #e8f5e9; color: #2e7d32; }
        .api-note { background: #fff3e0; border-radius: 8px; padding: 12px; font-size: 13px; margin-top: 12px; }
        .api-note code { background: #f5f5f5; padding: 2px 6px; border-radius: 4px; font-size: 12px; }
        .footer { text-align: center; padding: 24px; color: #999; font-size: 12px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>&#9764; Medical Prescription Portal</h1>
        <div class="user-info">
            <span>Welcome, {{ username }} ({{ role }})</span>
            <a href="/logout">Sign Out</a>
        </div>
    </div>
    <div class="container">
        <div class="welcome">
            <h2>Dashboard</h2>
            <p>View and manage patient prescriptions. Use the API explorer for advanced queries.</p>
        </div>

        <div class="info-card">
            <strong>GraphQL API Endpoint:</strong> <code>/graphql</code> &mdash; Available for data queries and exploration.
        </div>

        <div class="section">
            <h3>Registered Users</h3>
            <table>
                <tr><th>ID</th><th>Username</th><th>Role</th></tr>
                {% for u in users %}
                <tr>
                    <td>{{ u.id }}</td>
                    <td>{{ u.name }}</td>
                    <td><span class="badge badge-{{ u.role }}">{{ u.role }}</span></td>
                </tr>
                {% endfor %}
            </table>
        </div>

        <div class="section">
            <h3>My Prescriptions</h3>
            <table>
                <tr><th>ID</th><th>Medication</th><th>Notes</th></tr>
                {% for p in my_prescriptions %}
                <tr>
                    <td>{{ p.id }}</td>
                    <td>{{ p.medication }}</td>
                    <td>{{ p.notes }}</td>
                </tr>
                {% endfor %}
            </table>
        </div>

        <div class="api-note">
            <strong>API Documentation:</strong> The GraphQL endpoint supports schema introspection for API discovery.
            Try querying <code>/graphql</code> with a <code>__schema</code> query to explore available data.
        </div>
    </div>
    <div class="footer">Medical Prescription Portal v3.2.1 &mdash; Data served via GraphQL API</div>
</body>
</html>
"""


def login_required(f):
    """Simple decorator that checks for JWT in Authorization header OR cookie."""
    from functools import wraps

    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]

        if not token:
            token = request.cookies.get("auth_token")

        if not token:
            return render_template_string(LOGIN_PAGE, error="Please sign in to continue.")

        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            request.current_user = payload
        except jwt.ExpiredSignatureError:
            return render_template_string(LOGIN_PAGE, error="Session expired. Please sign in again.")
        except jwt.InvalidTokenError:
            return render_template_string(LOGIN_PAGE, error="Invalid session. Please sign in again.")

        return f(*args, **kwargs)

    return decorated


@app.route("/")
def index():
    token = request.cookies.get("auth_token", "")
    if not token:
        return render_template_string(LOGIN_PAGE)

    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return render_template_string(
            DASHBOARD_PAGE,
            username=payload["username"],
            role=payload["role"],
            users=[
                {"id": 1, "name": "admin", "role": "admin"},
                {"id": 2, "name": "doctor", "role": "doctor"},
                {"id": 3, "name": "patient", "role": "patient"},
            ],
            my_prescriptions=[
                {"id": i, "medication": PRESCRIPTION_TEMPLATES.get(int(payload.get("id", 3)), "").split("—")[0].strip() if "—" in PRESCRIPTION_TEMPLATES.get(int(payload.get("id", 3)), "") else PRESCRIPTION_TEMPLATES.get(int(payload.get("id", 3)), ""), "notes": PRESCRIPTION_TEMPLATES.get(int(payload.get("id", 3)), "")}
            ],
        )
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return render_template_string(LOGIN_PAGE)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template_string(LOGIN_PAGE)

    username = request.form.get("username", "").strip().lower()
    password = request.form.get("password", "")

    user = USERS_DB.get(username)
    if not user or user["password"] != password:
        return render_template_string(LOGIN_PAGE, error="Invalid username or password.")

    token = jwt.encode(
        {
            "username": username,
            "role": user["role"],
            "id": user["id"],
        },
        JWT_SECRET,
        algorithm="HS256",
    )

    resp = make_response(render_template_string(
        DASHBOARD_PAGE,
        username=username,
        role=user["role"],
        users=[
            {"id": 1, "name": "admin", "role": "admin"},
            {"id": 2, "name": "doctor", "role": "doctor"},
            {"id": 3, "name": "patient", "role": "patient"},
        ],
        my_prescriptions=[],
    ))
    resp.set_cookie("auth_token", token, httponly=True, max_age=3600)
    return resp


@app.route("/logout")
def logout():
    resp = make_response(render_template_string(LOGIN_PAGE))
    resp.set_cookie("auth_token", "", expires=0)
    return resp


@app.route("/graphql", methods=["GET", "POST"])
def graphql_view():
    if request.method == "GET":
        # GraphiQL IDE
        from graphene.tools import render_graphiql

        return render_graphiql(graphiql_version="3.2.0")

    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid request"}), 400

    query = data.get("query", "")
    variables = data.get("variables", {})

    # VULNERABILITY: No auth check before executing GraphQL query
    result = schema.execute(query, variables=variables)
    response_data = {"data": result.data}
    if result.errors:
        response_data["errors"] = [str(e) for e in result.errors]
    return jsonify(response_data)


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=False)
