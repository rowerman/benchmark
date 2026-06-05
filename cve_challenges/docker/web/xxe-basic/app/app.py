from flask import Flask, request, render_template_string
from lxml import etree

app = Flask(__name__)

HOME_PAGE = """<!DOCTYPE html>
<html>
<head>
    <title>Library Book Import Service</title>
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
        pre { background: #f8f9fa; border-radius: 8px; padding: 16px; overflow-x: auto; font-size: 14px; border: 1px solid #e0e0e0; }
        code { font-family: 'SF Mono', Monaco, 'Cascadia Code', monospace; }
        .endpoint { background: #e8f0fe; border-left: 4px solid #1a73e8; padding: 12px 16px; margin: 12px 0; border-radius: 0 8px 8px 0; }
        .endpoint .method { display: inline-block; background: #1a73e8; color: #fff; padding: 2px 10px; border-radius: 4px; font-size: 12px; font-weight: 600; margin-right: 8px; }
        .endpoint .path { font-family: 'SF Mono', Monaco, monospace; font-weight: 600; }
        .endpoint .desc { color: #555; margin-top: 8px; font-size: 14px; }
        .features { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-top: 20px; }
        .feature { background: #e8f0fe; border-radius: 8px; padding: 16px; }
        .feature h3 { color: #1a73e8; font-size: 14px; margin-bottom: 4px; }
        .feature p { color: #555; font-size: 13px; }
        .note { background: #fff3cd; border: 1px solid #ffc107; border-radius: 8px; padding: 16px; margin-top: 16px; font-size: 14px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Library Book Import Service</h1>
        <p class="subtitle">Import book records using XML data. Simple, fast, and reliable.</p>

        <div class="card">
            <h2>API Reference</h2>
            <div class="endpoint">
                <span class="method">POST</span><span class="path">/addbook</span>
                <div class="desc">Submit an XML book record for import into the library catalog.</div>
                <div class="desc"><strong>Content-Type:</strong> <code>application/xml</code></div>
                <div class="desc"><strong>Example XML payload:</strong></div>
                <pre><code>&lt;book&gt;
    &lt;title&gt;The Great Gatsby&lt;/title&gt;
    &lt;author&gt;F. Scott Fitzgerald&lt;/author&gt;
    &lt;isbn&gt;978-0-7432-7356-5&lt;/isbn&gt;
    &lt;year&gt;1925&lt;/year&gt;
&lt;/book&gt;</code></pre>
            </div>
        </div>

        <div class="card">
            <h2>Try It Out</h2>
            <p style="color: #555; margin-bottom: 12px;">Use curl or your favorite HTTP client to submit book data:</p>
            <pre><code>curl -X POST http://localhost:10113/addbook \\
  -H "Content-Type: application/xml" \\
  -d '&lt;book&gt;&lt;title&gt;My Book&lt;/title&gt;&lt;/book&gt;'</code></pre>
        </div>

        <div class="features">
            <div class="feature">
                <h3>XML Validation</h3>
                <p>We parse and validate your XML book records with industry-standard tools.</p>
            </div>
            <div class="feature">
                <h3>Entity Resolution</h3>
                <p>Full support for XML entities and document type definitions.</p>
            </div>
            <div class="feature">
                <h3>Metadata Extraction</h3>
                <p>Extract titles, authors, ISBNs, and publication years automatically.</p>
            </div>
            <div class="feature">
                <h3>Public API</h3>
                <p>Free to use — no authentication required for book import operations.</p>
            </div>
        </div>

        <div class="note">
            <strong>Note:</strong> This service accepts XML data from libraries and publishers.
            All standard XML features including DTDs and external entities are supported
            for maximum compatibility.
        </div>
    </div>
</body>
</html>"""


@app.route('/')
def home():
    return render_template_string(HOME_PAGE)


@app.route('/addbook', methods=['POST'])
def add_book():
    xml_data = request.get_data(as_text=True)
    if not xml_data.strip():
        return '<div class="error" style="color:#d93025;padding:16px;"><strong>Error:</strong> No XML data provided</div>'

    try:
        # VULNERABILITY: XXE - XMLParser allows entity resolution and network access
        parser = etree.XMLParser(no_network=False, resolve_entities=True)
        tree = etree.fromstring(xml_data.encode(), parser)
        title = tree.find('title').text if tree.find('title') is not None else 'Unknown'
        author = tree.find('author').text if tree.find('author') is not None else 'Unknown Author'

        result_html = f"""<!DOCTYPE html>
<html><head><title>Book Added Successfully</title>
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
    .value {{ color: #333; font-size: 16px; margin-top: 2px; word-break: break-all; }}
    .success {{ background: #e6f4ea; color: #137333; padding: 12px 16px; border-radius: 8px; margin-bottom: 16px; }}
</style>
</head><body>
<div class="card">
    <a href="/" class="back">&larr; Back to Home</a>
    <div class="success">Book imported successfully!</div>
    <h2>Book Details</h2>
    <div class="detail">
        <div class="label">Title</div>
        <div class="value">{title}</div>
    </div>
    <div class="detail">
        <div class="label">Author</div>
        <div class="value">{author}</div>
    </div>
</div>
</body></html>"""
        return result_html
    except Exception as e:
        error_html = f"""<!DOCTYPE html>
<html><head><title>Import Error</title>
<style>
    body {{ font-family: -apple-system, sans-serif; background: #f0f2f5; padding: 20px; }}
    .card {{ background: #fff; border-radius: 12px; padding: 24px; max-width: 600px; margin: 40px auto; }}
    .back {{ color: #1a73e8; text-decoration: none; font-weight: 500; }}
    .error {{ color: #d93025; background: #fce8e6; border-radius: 8px; padding: 16px; margin-top: 12px; }}
    .error-detail {{ color: #666; font-size: 14px; margin-top: 8px; font-family: monospace; }}
</style>
</head><body>
<div class="card">
    <a href="/" class="back">&larr; Back to Home</a>
    <h2 style="color:#d93025;">Import Failed</h2>
    <div class="error">Error parsing XML: {str(e)}</div>
</div>
</body></html>"""
        return error_html, 400


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
