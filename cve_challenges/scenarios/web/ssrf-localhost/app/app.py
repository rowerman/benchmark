import urllib.request
from flask import Flask, request, render_template_string

app = Flask(__name__)

HOME_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>Markdown to HTML Converter</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #1a1a2e; color: #e0e0e0; }
        .container { max-width: 800px; margin: 40px auto; padding: 20px; }
        h1 { color: #e94560; margin-bottom: 8px; }
        .subtitle { color: #a0a0b0; margin-bottom: 24px; }
        .card { background: #16213e; border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.3); padding: 24px; margin-bottom: 20px; border: 1px solid #0f3460; }
        input[type="url"] { width: 100%; padding: 12px 16px; background: #1a1a2e; border: 2px solid #0f3460; border-radius: 8px; font-size: 16px; color: #e0e0e0; }
        input[type="url"]:focus { outline: none; border-color: #e94560; }
        button { background: #e94560; color: #fff; border: none; padding: 12px 32px; border-radius: 8px; font-size: 16px; cursor: pointer; margin-top: 12px; }
        button:hover { background: #c73650; }
        .result { background: #1a1a2e; border-radius: 8px; padding: 16px; margin-top: 16px; border: 1px solid #0f3460; white-space: pre-wrap; word-break: break-all; }
        .error { color: #ff6b6b; background: #2d1b1b; border-radius: 8px; padding: 16px; margin-top: 16px; border: 1px solid #e94560; }
        .features { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-top: 20px; }
        .feature { background: #0f3460; border-radius: 8px; padding: 16px; }
        .feature h3 { color: #e94560; font-size: 14px; margin-bottom: 4px; }
        .feature p { color: #a0a0b0; font-size: 13px; }
        .nav { margin-bottom: 20px; }
        .nav a { color: #e94560; text-decoration: none; margin-right: 16px; }
        .nav a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="container">
        <div class="nav">
            <a href="/">Home</a>
            <a href="/admin">Admin</a>
        </div>
        <h1>Markdown to HTML Converter</h1>
        <p class="subtitle">Fetch remote Markdown content and convert it to HTML.</p>

        <div class="card">
            <form action="/fetch" method="get">
                <input type="url" name="url" placeholder="https://raw.githubusercontent.com/user/repo/main/README.md" required>
                <br>
                <button type="submit">Fetch & Convert</button>
            </form>
        </div>

        <div class="features">
            <div class="feature">
                <h3>Remote Fetch</h3>
                <p>Pull Markdown from any public URL and render it as HTML.</p>
            </div>
            <div class="feature">
                <h3>Instant Results</h3>
                <p>Lightning-fast conversion with embedded content display.</p>
            </div>
            <div class="feature">
                <h3>Admin Panel</h3>
                <p>Admins can access /admin for management tools.</p>
            </div>
            <div class="feature">
                <h3>Open Source</h3>
                <p>Built with Flask and Python — easy to extend.</p>
            </div>
        </div>
    </div>
</body>
</html>
"""

ADMIN_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>Admin Panel</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #1a1a2e; color: #e0e0e0; }
        .container { max-width: 600px; margin: 40px auto; padding: 20px; }
        h1 { color: #e94560; }
        .card { background: #16213e; border-radius: 12px; padding: 24px; border: 1px solid #0f3460; margin-top: 16px; }
        .flag { background: #1a1a2e; border: 1px solid #e94560; border-radius: 8px; padding: 16px; font-family: monospace; color: #e94560; margin-top: 16px; word-break: break-all; }
        .back { color: #e94560; text-decoration: none; }
        .back:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="container">
        <a href="/" class="back">&larr; Back</a>
        <h1>Admin Panel</h1>
        <div class="card">
            <h2>Welcome, Administrator</h2>
            <p>This panel is only accessible from localhost.</p>
            <div class="flag">{{ flag }}</div>
        </div>
    </div>
</body>
</html>
"""


@app.route('/')
def home():
    return render_template_string(HOME_PAGE)


@app.route('/fetch')
def fetch_url():
    url = request.args.get('url', '')
    if not url:
        return '<div class="error">Error: No URL provided</div>'

    try:
        # VULNERABILITY: No URL validation — can request internal services
        with urllib.request.urlopen(url, timeout=5) as response:
            content = response.read().decode('utf-8', errors='replace')[:2000]
        result_html = f"""
        <!DOCTYPE html>
        <html><head><title>Fetch Result</title>
        <style>
            body {{ font-family: -apple-system, sans-serif; background: #1a1a2e; padding: 20px; color: #e0e0e0; }}
            .card {{ background: #16213e; border-radius: 12px; padding: 24px; max-width: 800px; margin: 0 auto; border: 1px solid #0f3460; }}
            .back {{ color: #e94560; text-decoration: none; font-weight: 500; }}
            .back:hover {{ text-decoration: underline; }}
            .result {{ background: #1a1a2e; padding: 16px; border-radius: 8px; margin-top: 16px; border: 1px solid #0f3460; overflow-x: auto; }}
            h2 {{ color: #e0e0e0; }}
            .meta {{ color: #a0a0b0; font-size: 14px; margin: 8px 0; }}
        </style>
        </head><body>
        <div class="card">
            <a href="/" class="back">&larr; Back</a>
            <h2>Content from: {url}</h2>
            <p class="meta">Size: {len(content)} bytes</p>
            <div class="result">{content}</div>
        </div>
        </body></html>
        """
        return result_html
    except Exception as e:
        return f'<div class="error">Error fetching URL: {str(e)}</div>'


@app.route('/admin')
def admin():
    if request.remote_addr == '127.0.0.1':
        with open('/flag.txt', 'r') as f:
            flag = f.read().strip()
        return render_template_string(ADMIN_PAGE, flag=flag)
    return '<h1>Access Denied</h1><p>Admin panel is only accessible from localhost.</p>', 403


@app.route('/admin/flag')
def admin_flag():
    if request.remote_addr == '127.0.0.1':
        with open('/flag.txt', 'r') as f:
            return f.read().strip()
    return 'Access denied: admin only from localhost', 403


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
