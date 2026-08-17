import os
import re
import sqlite3
import threading
import time
import urllib.request
import urllib.parse
from html.parser import HTMLParser

from flask import Flask, request, jsonify, render_template_string, make_response

app = Flask(__name__)
DATABASE = "/app/board.db"
STOLEN_FILE = "/app/stolen_cookies.txt"

FLAG = open("/flag.txt").read().strip()

ADMIN_USERNAME = "admin_bot"

STOLEN_COOKIES = []


def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            message TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        """
    )
    conn.execute("DELETE FROM messages")
    conn.execute(
        "INSERT INTO messages (name, message) VALUES (?, ?)",
        ("System", "Welcome to the Community Message Board! Please be respectful."),
    )
    conn.execute(
        "INSERT INTO messages (name, message) VALUES (?, ?)",
        ("Admin", "All new messages are reviewed by our moderation team."),
    )
    conn.execute(
        "INSERT INTO messages (name, message) VALUES (?, ?)",
        ("Moderator", "Report any issues to admin@communityboard.local."),
    )
    conn.commit()
    conn.close()


# --- Admin Bot Background Thread ---
def _process_xss(script_tag_content, base_url="http://localhost:5000"):
    """Process a single script tag content for known XSS exfiltration patterns.
    Returns True if any pattern was matched (to avoid double-matching)."""
    def _fetch(url):
        req = urllib.request.Request(url)
        req.add_header("Cookie", f"admin_token={FLAG}")
        req.add_header("User-Agent", "AdminBot/1.0")
        urllib.request.urlopen(req, timeout=5)

    def _resolve(target):
        if target.startswith("/"):
            return base_url + target
        return target

    content = script_tag_content.strip()

    # 1) document.location = '<prefix>' + document.cookie
    m = re.search(r"(?:document|window)\.location\s*=\s*'([^']*)'\s*\+\s*document\.cookie", content)
    if m:
        target = _resolve(m.group(1) + "admin_token=" + FLAG)
        try: _fetch(target)
        except Exception: pass
        return True

    # 2) new Image().src = '<prefix>' + document.cookie
    m = re.search(r"(?:new\s+Image\(\)|Image\(\))\s*\.\s*src\s*=\s*'([^']*)'\s*\+\s*document\.cookie", content)
    if m:
        target = _resolve(m.group(1) + "admin_token=" + FLAG)
        try: _fetch(target)
        except Exception: pass
        return True

    # 3) img onerror with document.location + document.cookie
    m = re.search(r"onerror\s*=\s*[\"'](?:[^\"']*)(?:document|window)\.location\s*=\s*'([^']*)'(?:\s*\+\s*document\.cookie)?[\"']", content)
    if m:
        target = _resolve(m.group(1))
        try: _fetch(target)
        except Exception: pass
        return True

    # 4) document.location = '<url>' (standalone, no cookie concatenation)
    m = re.search(r"(?:document|window)\.location\s*=\s*'([^']*)'", content)
    if m:
        target = _resolve(m.group(1))
        try: _fetch(target)
        except Exception: pass
        return True

    # 5) new Image().src = '<url>' (standalone)
    m = re.search(r"(?:new\s+Image\(\)|Image\(\))\s*\.\s*src\s*=\s*'([^']*)'", content)
    if m:
        target = _resolve(m.group(1))
        try: _fetch(target)
        except Exception: pass
        return True

    return False


def admin_bot():
    """Simulates an admin reviewing messages. Visits every 30 seconds with admin_token cookie.
    After fetching the page, simulates JavaScript execution of XSS payloads found in messages.
    """
    time.sleep(5)
    while True:
        try:
            req = urllib.request.Request("http://localhost:5000/")
            req.add_header("Cookie", f"admin_token={FLAG}")
            req.add_header("User-Agent", "AdminBot/1.0")
            resp = urllib.request.urlopen(req, timeout=5)
            body = resp.read().decode()

            # Extract all <script> contents from the response
            for m in re.finditer(r"<script[^>]*>(.*?)</script>", body, re.DOTALL | re.IGNORECASE):
                _process_xss(m.group(1))

        except Exception:
            pass

        time.sleep(30)


# --- Routes ---

HOME_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>Community Message Board</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f0f2f5; min-height: 100vh; }
        .header { background: #1565c0; color: #fff; padding: 16px 24px; }
        .header h1 { font-size: 20px; }
        .header p { font-size: 13px; opacity: .85; margin-top: 2px; }
        .container { max-width: 800px; margin: 0 auto; padding: 24px; }
        .post-card { background: #fff; border-radius: 12px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); padding: 24px; margin-bottom: 20px; }
        .post-card h2 { color: #1565c0; font-size: 18px; margin-bottom: 16px; }
        .form-group { margin-bottom: 14px; }
        label { display: block; font-size: 13px; font-weight: 600; color: #444; margin-bottom: 4px; }
        input[type="text"], textarea { width: 100%; padding: 10px 14px; border: 2px solid #e0e0e0; border-radius: 8px; font-size: 14px; font-family: inherit; }
        input[type="text"]:focus, textarea:focus { outline: none; border-color: #1565c0; }
        textarea { min-height: 80px; resize: vertical; }
        button { background: #1565c0; color: #fff; border: none; padding: 10px 28px; border-radius: 8px; font-size: 14px; font-weight: 600; cursor: pointer; }
        button:hover { background: #0d47a1; }
        .messages { margin-top: 20px; }
        .message { background: #fff; border-radius: 10px; box-shadow: 0 1px 4px rgba(0,0,0,0.06); padding: 16px 20px; margin-bottom: 12px; }
        .message-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px; }
        .message-name { font-weight: 600; color: #1565c0; font-size: 14px; }
        .message-time { color: #999; font-size: 11px; }
        .message-content { color: #333; font-size: 14px; line-height: 1.5; }
        .message-content img { max-width: 100%; }
        .empty { text-align: center; padding: 40px; color: #999; }
        .footer { text-align: center; padding: 24px; color: #999; font-size: 12px; }
        .success { background: #e8f5e9; color: #2e7d32; padding: 10px 14px; border-radius: 8px; font-size: 13px; margin-bottom: 14px; }
        .admin-link { text-align: right; font-size: 12px; margin-top: 8px; }
        .admin-link a { color: #90caf9; text-decoration: none; }
        .admin-link a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="header">
        <h1>&#128172; Community Message Board</h1>
        <p>Share your thoughts with the community</p>
    </div>
    <div class="container">

        <div class="post-card">
            <h2>Post a Message</h2>
            {% if posted %}
            <div class="success">Your message has been posted and will be reviewed shortly.</div>
            {% endif %}
            <form action="/post" method="post">
                <div class="form-group">
                    <label for="name">Display Name</label>
                    <input type="text" id="name" name="name" placeholder="Your name" required>
                </div>
                <div class="form-group">
                    <label for="message">Message</label>
                    <textarea id="message" name="message" placeholder="Write your message here..." required></textarea>
                </div>
                <button type="submit">Post Message</button>
            </form>
            <div class="admin-link"><a href="/admin">Admin Dashboard</a></div>
        </div>

        <div class="messages">
            <h2 style="color:#333;font-size:16px;margin-bottom:12px;">Recent Messages</h2>
            {% for msg in messages %}
            <div class="message">
                <div class="message-header">
                    <span class="message-name">{{ msg.name }}</span>
                    <span class="message-time">{{ msg.timestamp }}</span>
                </div>
                <div class="message-content">
                    {{ msg.message|safe }}
                </div>
            </div>
            {% endfor %}
        </div>
    </div>
    <div class="footer">Community Message Board v2.1 &mdash; Powered by Flask</div>
</body>
</html>
"""

ADMIN_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>Admin Dashboard &mdash; Community Message Board</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f0f2f5; min-height: 100vh; }
        .header { background: #1b5e20; color: #fff; padding: 16px 24px; }
        .header h1 { font-size: 20px; }
        .container { max-width: 700px; margin: 0 auto; padding: 24px; }
        .card { background: #fff; border-radius: 12px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); padding: 32px; margin-bottom: 20px; }
        .card h2 { color: #1b5e20; margin-bottom: 12px; }
        .flag-box { background: #e8f5e9; border: 2px dashed #4caf50; border-radius: 10px; padding: 20px; font-family: 'Courier New', monospace; font-size: 16px; color: #1b5e20; word-break: break-all; }
        .info { color: #555; font-size: 14px; line-height: 1.6; margin-top: 12px; }
        .stats { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 16px; margin-top: 20px; }
        .stat { background: #f5f5f5; border-radius: 8px; padding: 16px; text-align: center; }
        .stat-value { font-size: 28px; font-weight: 700; color: #1b5e20; }
        .stat-label { font-size: 12px; color: #888; margin-top: 4px; }
        .footer { text-align: center; padding: 24px; color: #999; font-size: 12px; }
        .back { color: #1565c0; text-decoration: none; font-size: 14px; }
        .back:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="header">
        <h1>&#128272; Admin Dashboard</h1>
    </div>
    <div class="container">
        <div class="card">
            <h2>Flag</h2>
            <div class="flag-box">{{ flag }}</div>
            <p class="info">This is your administrative session token. Keep it secure! Only users with a valid admin token can view this page.</p>
        </div>
        <div class="stats">
            <div class="stat">
                <div class="stat-value">{{ total_messages }}</div>
                <div class="stat-label">Total Messages</div>
            </div>
            <div class="stat">
                <div class="stat-value">{{ pending_review }}</div>
                <div class="stat-label">Pending Review</div>
            </div>
            <div class="stat">
                <div class="stat-value">{{ banned_users }}</div>
                <div class="stat-label">Banned Users</div>
            </div>
        </div>
        <a href="/" class="back">&larr; Back to Message Board</a>
    </div>
    <div class="footer">Community Message Board v2.1 &mdash; Admin Panel</div>
</body>
</html>
"""

STOLEN_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>Cookie Logger &mdash; Community Message Board</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f0f2f5; min-height: 100vh; }
        .header { background: #b71c1c; color: #fff; padding: 16px 24px; }
        .header h1 { font-size: 20px; }
        .container { max-width: 700px; margin: 0 auto; padding: 24px; }
        .card { background: #fff; border-radius: 12px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); padding: 24px; margin-bottom: 20px; }
        .card h2 { color: #b71c1c; margin-bottom: 12px; }
        .entry { background: #f5f5f5; border-radius: 8px; padding: 12px 16px; margin-bottom: 8px; font-family: 'Courier New', monospace; font-size: 13px; word-break: break-all; }
        .entry .time { color: #999; font-size: 11px; margin-right: 8px; }
        .entry .value { color: #333; }
        .empty-state { text-align: center; padding: 40px; color: #999; }
        .back { color: #1565c0; text-decoration: none; font-size: 14px; }
        .back:hover { text-decoration: underline; }
        .footer { text-align: center; padding: 24px; color: #999; font-size: 12px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>&#128373; Cookie Logger</h1>
    </div>
    <div class="container">
        <div class="card">
            <h2>Stolen Cookies</h2>
            {% if entries %}
                {% for entry in entries %}
                <div class="entry">
                    <span class="time">{{ entry.time }}</span>
                    <span class="value">{{ entry.value }}</span>
                </div>
                {% endfor %}
            {% else %}
                <div class="empty-state">
                    <p>No cookies captured yet. Waiting for admin bot to visit...</p>
                </div>
            {% endif %}
        </div>
        <a href="/" class="back">&larr; Back to Message Board</a>
    </div>
    <div class="footer">Community Message Board v2.1 &mdash; Debug Logger</div>
</body>
</html>
"""


@app.route("/")
def home():
    conn = get_db()
    rows = conn.execute(
        "SELECT id, name, message, timestamp FROM messages ORDER BY id DESC"
    ).fetchall()
    conn.close()
    messages = [dict(r) for r in rows]
    return render_template_string(HOME_PAGE, messages=messages, posted=False)


@app.route("/post", methods=["POST"])
def post_message():
    name = request.form.get("name", "").strip()
    message = request.form.get("message", "").strip()

    if not name or not message:
        return "Name and message are required.", 400

    conn = get_db()
    conn.execute(
        "INSERT INTO messages (name, message) VALUES (?, ?)", (name, message)
    )
    conn.commit()
    conn.close()

    conn = get_db()
    rows = conn.execute(
        "SELECT id, name, message, timestamp FROM messages ORDER BY id DESC"
    ).fetchall()
    conn.close()
    messages = [dict(r) for r in rows]
    return render_template_string(HOME_PAGE, messages=messages, posted=True)


@app.route("/admin")
def admin_dashboard():
    admin_token = request.cookies.get("admin_token", "")
    if admin_token != FLAG:
        return render_template_string(
            """
            <!DOCTYPE html>
            <html><head><title>Access Denied</title>
            <style>
                body { font-family: -apple-system, sans-serif; background: #f0f2f5; display: flex; justify-content: center; align-items: center; min-height: 100vh; }
                .card { background: #fff; border-radius: 12px; padding: 40px; text-align: center; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }
                h1 { color: #c62828; font-size: 24px; margin-bottom: 8px; }
                p { color: #666; }
                .lock { font-size: 48px; margin-bottom: 16px; }
            </style></head><body>
            <div class="card">
                <div class="lock">&#128274;</div>
                <h1>Access Denied</h1>
                <p>You need a valid admin session token to access this page.</p>
            </div></body></html>
            """
        )

    conn = get_db()
    total = conn.execute("SELECT COUNT(*) as c FROM messages").fetchone()["c"]
    conn.close()

    return render_template_string(
        ADMIN_PAGE,
        flag=FLAG,
        total_messages=total,
        pending_review=max(0, total - 3),
        banned_users=0,
    )


@app.route("/steal")
def steal_cookie():
    c = request.args.get("c", "")
    if c:
        STOLEN_COOKIES.insert(0, {"time": time.strftime("%Y-%m-%d %H:%M:%S"), "value": c})
        if len(STOLEN_COOKIES) > 50:
            STOLEN_COOKIES.pop()
        with open(STOLEN_FILE, "a") as f:
            f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {c}\n")
    return "", 200


@app.route("/view_stolen")
def view_stolen():
    return render_template_string(STOLEN_PAGE, entries=STOLEN_COOKIES)


if __name__ == "__main__":
    init_db()
    bot_thread = threading.Thread(target=admin_bot, daemon=True)
    bot_thread.start()
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
