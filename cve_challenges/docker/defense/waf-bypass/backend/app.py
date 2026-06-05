#!/usr/bin/env python3
"""Vulnerable Flask app with SQLi in POST /login"""

import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json(silent=True) or {}
    user = data.get('user', '')
    password = data.get('pass', '')
    if not user or not password:
        return jsonify({'error': 'Missing user or pass'}), 400
    conn = sqlite3.connect('/app/users.db')
    c = conn.cursor()
    query = f"SELECT * FROM users WHERE username='{user}' AND password='{password}'"
    try:
        c.execute(query)
        row = c.fetchone()
        if row:
            # Grant access — reveals admin's password (the flag) in response
            return jsonify({'success': True, 'data': {'id': row[0], 'username': row[1], 'password': row[2]}})
        else:
            return jsonify({'success': False, 'message': 'Invalid credentials'}), 401
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok'}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
