import requests
from flask import Flask, request, render_template_string

app = Flask(__name__)

HOME_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>URL Preview Service</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f0f2f5; color: #333; }
        .container { max-width: 800px; margin: 40px auto; padding: 20px; }
        h1 { color: #1a73e8; margin-bottom: 8px; }
        .subtitle { color: #666; margin-bottom: 24px; }
        .card { background: #fff; border-radius: 12px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); padding: 24px; margin-bottom: 20px; }
        input[type="url"] { width: 100%; padding: 12px 16px; border: 2px solid #e0e0e0; border-radius: 8px; font-size: 16px; }
        input[type="url"]:focus { outline: none; border-color: #1a73e8; }
        button { background: #1a73e8; color: #fff; border: none; padding: 12px 32px; border-radius: 8px; font-size: 16px; cursor: pointer; margin-top: 12px; }
        button:hover { background: #1557b0; }
        .result { background: #f8f9fa; border-radius: 8px; padding: 16px; margin-top: 16px; white-space: pre-wrap; word-break: break-all; }
        .error { color: #d93025; background: #fce8e6; border-radius: 8px; padding: 16px; margin-top: 16px; }
        .features { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-top: 20px; }
        .feature { background: #e8f0fe; border-radius: 8px; padding: 16px; }
        .feature h3 { color: #1a73e8; font-size: 14px; margin-bottom: 4px; }
        .feature p { color: #555; font-size: 13px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>URL Preview Service</h1>
        <p class="subtitle">Enter a URL and we'll fetch a preview of its content for you.</p>

        <div class="card">
            <form action="/fetch" method="get">
                <input type="url" name="url" placeholder="https://example.com" required>
                <br>
                <button type="submit">Fetch Preview</button>
            </form>
        </div>

        <div class="features">
            <div class="feature">
                <h3>Quick Previews</h3>
                <p>Get a snapshot of any publicly accessible URL in seconds.</p>
            </div>
            <div class="feature">
                <h3>Content Extraction</h3>
                <p>We retrieve the raw content so you can inspect it.</p>
            </div>
            <div class="feature">
                <h3>No Registration</h3>
                <p>Free to use — just paste and go.</p>
            </div>
            <div class="feature">
                <h3>Lightning Fast</h3>
                <p>Our service fetches pages quickly with a 5-second timeout.</p>
            </div>
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
        # VULNERABILITY: No URL validation — SSRF possible
        resp = requests.get(url, timeout=5)
        content = resp.text[:2000]
        result_html = f"""
        <!DOCTYPE html>
        <html><head><title>Preview Result</title>
        <style>
            body {{ font-family: -apple-system, sans-serif; background: #f0f2f5; padding: 20px; }}
            .card {{ background: #fff; border-radius: 12px; padding: 24px; max-width: 800px; margin: 0 auto; }}
            .back {{ color: #1a73e8; text-decoration: none; font-weight: 500; }}
            .back:hover {{ text-decoration: underline; }}
            .result {{ background: #f8f9fa; padding: 16px; border-radius: 8px; margin-top: 16px; overflow-x: auto; }}
            h2 {{ color: #333; }}
            .meta {{ color: #666; font-size: 14px; margin: 8px 0; }}
        </style>
        </head><body>
        <div class="card">
            <a href="/" class="back">&larr; Back</a>
            <h2>Preview: {url}</h2>
            <p class="meta">Status: {resp.status_code} | Size: {len(resp.text)} bytes</p>
            <div class="result">{content}</div>
        </div>
        </body></html>
        """
        return result_html
    except Exception as e:
        return f'<div class="error">Error fetching URL: {str(e)}</div>'


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
