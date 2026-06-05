"""CI-04: Unprotected Webhook Endpoint

A CI webhook receiver that doesn't verify HMAC signatures.
Anyone can POST to /webhook and get build output (with flag).
"""
import os
from flask import Flask, request, jsonify

app = Flask(__name__)
FLAG = os.environ.get('FLAG', 'flag{ci-04-default}')


@app.route('/webhook', methods=['POST'])
def webhook():
    """Unprotected webhook endpoint - no signature verification."""
    data = request.get_json(silent=True) or {}
    repo = data.get('repo', 'unknown')
    branch = data.get('branch', 'main')

    # Simulate build output that leaks the flag
    output = (
        f"[CI] Build triggered for {repo} ({branch})\n"
        f"[CI] Cloning repository... OK\n"
        f"[CI] Installing dependencies... OK\n"
        f"[CI] Running tests... OK\n"
        f"[CI] Deploying to production... OK\n"
        f"[CI] Build secret: {FLAG}\n"
        f"[CI] Build completed successfully."
    )

    return jsonify({
        'status': 'success',
        'job_id': 'ci-0001',
        'output': output,
    })


@app.route('/', methods=['GET'])
def index():
    return jsonify({
        'service': 'CI Webhook Receiver',
        'endpoint': 'POST /webhook',
        'status': 'running',
    })


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
