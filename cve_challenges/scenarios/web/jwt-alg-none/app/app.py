import os
import jwt
from flask import Flask, request, jsonify, render_template_string
from functools import wraps

app = Flask(__name__)

# Hardcoded secret key (intentionally weak for the challenge)
SECRET_KEY = "super_secret_key_2024_change_me_now!"
FLAG = os.getenv('FLAG', 'flag{web-15-default}')

# Valid users
USERS = {
    'guest': 'guest123',
    'admin': 'supersecret_admin'
}

HOME_PAGE = """<!DOCTYPE html>
<html>
<head>
    <title>Company Employee Portal</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f0f2f5; color: #333; }
        .container { max-width: 800px; margin: 40px auto; padding: 20px; }
        h1 { color: #1a73e8; margin-bottom: 8px; }
        .subtitle { color: #666; margin-bottom: 24px; }
        .card { background: #fff; border-radius: 12px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); padding: 24px; margin-bottom: 20px; }
        .card h2 { color: #333; margin-bottom: 12px; }
        .form-group { margin-bottom: 16px; }
        .form-group label { display: block; color: #555; font-size: 14px; font-weight: 500; margin-bottom: 4px; }
        .form-group input { width: 100%; padding: 12px 16px; border: 2px solid #e0e0e0; border-radius: 8px; font-size: 16px; }
        .form-group input:focus { outline: none; border-color: #1a73e8; }
        button { background: #1a73e8; color: #fff; border: none; padding: 12px 32px; border-radius: 8px; font-size: 16px; cursor: pointer; }
        button:hover { background: #1557b0; }
        .endpoints { margin-top: 20px; }
        .endpoint { background: #f8f9fa; border-left: 4px solid #1a73e8; padding: 12px 16px; margin: 8px 0; border-radius: 0 8px 8px 0; }
        .endpoint .method { display: inline-block; padding: 2px 10px; border-radius: 4px; font-size: 12px; font-weight: 600; margin-right: 8px; color: #fff; }
        .method-get { background: #34a853; }
        .method-post { background: #1a73e8; }
        .endpoint .path { font-family: 'SF Mono', Monaco, monospace; font-weight: 600; }
        .endpoint .desc { color: #555; margin-top: 8px; font-size: 14px; }
        code { font-family: 'SF Mono', Monaco, 'Cascadia Code', monospace; background: #f1f3f4; padding: 2px 6px; border-radius: 4px; font-size: 14px; }
        pre { background: #f8f9fa; border-radius: 8px; padding: 16px; overflow-x: auto; font-size: 14px; border: 1px solid #e0e0e0; }
        .features { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-top: 20px; }
        .feature { background: #e8f0fe; border-radius: 8px; padding: 16px; }
        .feature h3 { color: #1a73e8; font-size: 14px; margin-bottom: 4px; }
        .feature p { color: #555; font-size: 13px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Company Employee Portal</h1>
        <p class="subtitle">Secure access to employee profiles and administrative functions.</p>

        <div class="card">
            <h2>Login</h2>
            <form id="login-form">
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
            <div id="result" style="margin-top: 16px;"></div>
        </div>

        <div class="card">
            <h2>API Endpoints</h2>
            <div class="endpoints">
                <div class="endpoint">
                    <span class="method method-post">POST</span><span class="path">/login</span>
                    <div class="desc">Authenticate and receive a JWT access token.</div>
                    <div class="desc"><strong>Body:</strong> <code>{"username": "...", "password": "..."}</code></div>
                </div>
                <div class="endpoint">
                    <span class="method method-get">GET</span><span class="path">/profile</span>
                    <div class="desc">View your profile information. Requires <code>Authorization: Bearer &lt;token&gt;</code> header.</div>
                </div>
                <div class="endpoint">
                    <span class="method method-get">GET</span><span class="path">/admin</span>
                    <div class="desc">Admin panel (restricted to administrators only).</div>
                </div>
            </div>
        </div>

        <div class="features">
            <div class="feature">
                <h3>JWT Authentication</h3>
                <p>Secure token-based authentication using industry-standard JSON Web Tokens.</p>
            </div>
            <div class="feature">
                <h3>Role-Based Access</h3>
                <p>Granular access control with user and administrator roles.</p>
            </div>
            <div class="feature">
                <h3>Profile Management</h3>
                <p>View your personal details and account information.</p>
            </div>
            <div class="feature">
                <h3>Admin Dashboard</h3>
                <p>Administrative interface for managing company resources (admin only).</p>
            </div>
        </div>
    </div>

    <script>
        document.getElementById('login-form').addEventListener('submit', async function(e) {
            e.preventDefault();
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;

            try {
                const response = await fetch('/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password })
                });
                const data = await response.json();
                const resultDiv = document.getElementById('result');

                if (response.ok) {
                    resultDiv.innerHTML = '<div style="background:#e6f4ea;color:#137333;padding:12px 16px;border-radius:8px;">' +
                        '<strong>Login successful!</strong><br>' +
                        'Token: <code style="word-break:break-all;">' + data.token + '</code></div>';
                } else {
                    resultDiv.innerHTML = '<div style="background:#fce8e6;color:#d93025;padding:12px 16px;border-radius:8px;">' +
                        '<strong>Error:</strong> ' + (data.error || 'Login failed') + '</div>';
                }
            } catch (err) {
                document.getElementById('result').innerHTML = '<div style="background:#fce8e6;color:#d93025;padding:12px 16px;border-radius:8px;">Network error</div>';
            }
        });
    </script>
</body>
</html>"""


def get_jwt_payload():
    """Extract and decode JWT from Authorization header."""
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return None
    token = auth_header.split(' ', 1)[1]
    try:
        # VULNERABILITY: verify_signature=False means the app accepts ANY token
        # including forged tokens with alg: none
        payload = jwt.decode(token, options={"verify_signature": False})
        return payload
    except Exception:
        return None


@app.route('/')
def home():
    return render_template_string(HOME_PAGE)


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({'error': 'Invalid JSON payload'}), 400

    username = data.get('username', '')
    password = data.get('password', '')

    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400

    if username not in USERS:
        return jsonify({'error': 'Invalid username or password'}), 401

    if USERS[username] != password:
        return jsonify({'error': 'Invalid username or password'}), 401

    # Create JWT with appropriate role
    if username == 'admin':
        payload = {'username': 'admin', 'role': 'admin'}
    else:
        payload = {'username': username, 'role': 'user'}

    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
    return jsonify({'token': token, 'username': payload['username'], 'role': payload['role']})


@app.route('/profile')
def profile():
    payload = get_jwt_payload()
    if not payload:
        return jsonify({'error': 'Invalid or missing token. Provide Authorization: Bearer <token>'}), 401

    username = payload.get('username', 'unknown')
    role = payload.get('role', 'unknown')

    profile_html = f"""<!DOCTYPE html>
<html><head><title>User Profile</title>
<style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f0f2f5; padding: 20px; color: #333; }}
    .card {{ background: #fff; border-radius: 12px; padding: 24px; max-width: 600px; margin: 40px auto; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }}
    .back {{ color: #1a73e8; text-decoration: none; font-weight: 500; }}
    .back:hover {{ text-decoration: underline; }}
    h2 {{ color: #333; margin-bottom: 16px; }}
    .detail {{ padding: 10px 0; border-bottom: 1px solid #eee; }}
    .detail:last-child {{ border-bottom: none; }}
    .label {{ color: #666; font-size: 13px; text-transform: uppercase; letter-spacing: 0.5px; }}
    .value {{ color: #333; font-size: 16px; margin-top: 2px; }}
    .avatar {{ width: 64px; height: 64px; border-radius: 50%; background: #1a73e8; display: flex; align-items: center; justify-content: center; color: #fff; font-size: 28px; font-weight: 600; margin-bottom: 16px; }}
</style>
</head><body>
<div class="card">
    <a href="/" class="back">&larr; Back to Home</a>
    <div class="avatar">{username[0].upper()}</div>
    <h2>User Profile</h2>
    <div class="detail">
        <div class="label">Username</div>
        <div class="value">{username}</div>
    </div>
    <div class="detail">
        <div class="label">Role</div>
        <div class="value">{role}</div>
    </div>
    <div class="detail">
        <div class="label">Employee Status</div>
        <div class="value">Active</div>
    </div>
</div>
</body></html>"""
    return profile_html


@app.route('/admin')
def admin():
    payload = get_jwt_payload()
    if not payload:
        return jsonify({'error': 'Invalid or missing token. Provide Authorization: Bearer <token>'}), 401

    username = payload.get('username', 'unknown')
    role = payload.get('role', 'unknown')

    if role == 'admin':
        admin_html = f"""<!DOCTYPE html>
<html><head><title>Admin Panel</title>
<style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f0f2f5; padding: 20px; color: #333; }}
    .card {{ background: #fff; border-radius: 12px; padding: 24px; max-width: 600px; margin: 40px auto; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }}
    .back {{ color: #1a73e8; text-decoration: none; font-weight: 500; }}
    .back:hover {{ text-decoration: underline; }}
    h2 {{ color: #333; margin-bottom: 16px; }}
    .flag {{ background: #fce8e6; border: 2px solid #d93025; border-radius: 8px; padding: 16px; margin-top: 16px; }}
    .flag .value {{ font-family: 'SF Mono', Monaco, monospace; font-size: 18px; color: #d93025; font-weight: 600; word-break: break-all; }}
    .label {{ color: #666; font-size: 13px; text-transform: uppercase; letter-spacing: 0.5px; }}
    .section {{ padding: 10px 0; border-bottom: 1px solid #eee; }}
</style>
</head><body>
<div class="card">
    <a href="/" class="back">&larr; Back to Home</a>
    <h2>Admin Panel</h2>
    <div class="section">
        <div class="label">Admin User</div>
        <div style="font-size:16px;margin-top:2px;">{username}</div>
    </div>
    <div class="section">
        <div class="label">Access Level</div>
        <div style="font-size:16px;margin-top:2px;color:#137333;">Full Administrative Access</div>
    </div>
    <div class="flag">
        <div class="label">Server Flag</div>
        <div class="value">{FLAG}</div>
    </div>
</div>
</body></html>"""
        return admin_html
    else:
        denied_html = f"""<!DOCTYPE html>
<html><head><title>Access Denied</title>
<style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f0f2f5; padding: 20px; color: #333; }}
    .card {{ background: #fff; border-radius: 12px; padding: 24px; max-width: 600px; margin: 40px auto; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }}
    .back {{ color: #1a73e8; text-decoration: none; font-weight: 500; }}
    h2 {{ color: #d93025; margin-bottom: 12px; }}
    .error {{ color: #d93025; background: #fce8e6; border-radius: 8px; padding: 16px; }}
    .detail {{ color: #666; margin-top: 12px; font-size: 14px; }}
</style>
</head><body>
<div class="card">
    <a href="/" class="back">&larr; Back to Home</a>
    <h2>Access Denied</h2>
    <div class="error">Admin access required. Your role is '{role}'.</div>
    <div class="detail">If you believe this is an error, please contact your system administrator.</div>
</div>
</body></html>"""
        return denied_html, 403


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
