from fastapi import FastAPI, UploadFile, File, Request
from fastapi.responses import HTMLResponse
from lxml import etree

app = FastAPI(title="Profile Avatar Upload Service")

HOME_PAGE = """<!DOCTYPE html>
<html>
<head>
    <title>Profile Avatar Upload Service</title>
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
        .upload-zone { border: 2px dashed #1a73e8; border-radius: 12px; padding: 40px; text-align: center; background: #f8faff; }
        .upload-zone.dragover { background: #e8f0fe; border-color: #1557b0; }
        .upload-zone input[type="file"] { display: none; }
        .upload-btn { background: #1a73e8; color: #fff; border: none; padding: 12px 32px; border-radius: 8px; font-size: 16px; cursor: pointer; }
        .upload-btn:hover { background: #1557b0; }
        .upload-zone p { color: #666; margin-top: 12px; font-size: 14px; }
        pre { background: #f8f9fa; border-radius: 8px; padding: 16px; overflow-x: auto; font-size: 14px; border: 1px solid #e0e0e0; }
        code { font-family: 'SF Mono', Monaco, 'Cascadia Code', monospace; }
        .features { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-top: 20px; }
        .feature { background: #e8f0fe; border-radius: 8px; padding: 16px; }
        .feature h3 { color: #1a73e8; font-size: 14px; margin-bottom: 4px; }
        .feature p { color: #555; font-size: 13px; }
        .format-badge { display: inline-block; background: #34a853; color: #fff; padding: 2px 10px; border-radius: 12px; font-size: 12px; font-weight: 600; }
        .note { background: #fff3cd; border: 1px solid #ffc107; border-radius: 8px; padding: 16px; margin-top: 16px; font-size: 14px; }
        .icon { font-size: 48px; margin-bottom: 16px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Profile Avatar Upload Service</h1>
        <p class="subtitle">Upload SVG avatars for your user profile. We process and display them instantly.</p>

        <div class="card">
            <h2>Upload Your Avatar</h2>
            <div class="upload-zone" id="dropzone">
                <div class="icon">&#128100;</div>
                <p>Drag and drop an SVG file here, or click below to browse</p>
                <form action="/upload" method="post" enctype="multipart/form-data" id="upload-form" style="margin-top: 16px;">
                    <input type="file" name="file" accept=".svg,image/svg+xml" id="file-input">
                    <button type="button" class="upload-btn" onclick="document.getElementById('file-input').click()">Choose SVG File</button>
                    <button type="submit" class="upload-btn" style="background: #34a853; margin-left: 8px;">Upload</button>
                </form>
                <p style="margin-top: 12px;">Accepted format: <span class="format-badge">SVG</span> (Scalable Vector Graphics)</p>
            </div>
        </div>

        <div class="card">
            <h2>Supported Features</h2>
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px;">
                <div style="background: #e8f0fe; border-radius: 8px; padding: 12px;">
                    <h3 style="color: #1a73e8; font-size: 14px;">SVG Parsing</h3>
                    <p style="color: #555; font-size: 13px;">Full SVG specification support with dimension extraction.</p>
                </div>
                <div style="background: #e8f0fe; border-radius: 8px; padding: 12px;">
                    <h3 style="color: #1a73e8; font-size: 14px;">DTD Support</h3>
                    <p style="color: #555; font-size: 13px;">Document Type Definitions are fully resolved for compatibility.</p>
                </div>
                <div style="background: #e8f0fe; border-radius: 8px; padding: 12px;">
                    <h3 style="color: #1a73e8; font-size: 14px;">Entity Resolution</h3>
                    <p style="color: #555; font-size: 13px;">Internal and external entities are resolved during parsing.</p>
                </div>
                <div style="background: #e8f0fe; border-radius: 8px; padding: 12px;">
                    <h3 style="color: #1a73e8; font-size: 14px;">Dimension Analysis</h3>
                    <p style="color: #555; font-size: 13px;">Automatic extraction of width, height, and viewBox attributes.</p>
                </div>
            </div>
        </div>

        <div class="note">
            <strong>Note:</strong> Only SVG files are accepted. We use a robust XML parser
            with full entity resolution to ensure your vector graphics are processed correctly.
            Maximum file size: 1 MB.
        </div>
    </div>

    <script>
        const dropzone = document.getElementById('dropzone');
        const fileInput = document.getElementById('file-input');

        dropzone.addEventListener('dragover', function(e) {
            e.preventDefault();
            this.classList.add('dragover');
        });

        dropzone.addEventListener('dragleave', function(e) {
            e.preventDefault();
            this.classList.remove('dragover');
        });

        dropzone.addEventListener('drop', function(e) {
            e.preventDefault();
            this.classList.remove('dragover');
            if (e.dataTransfer.files.length) {
                fileInput.files = e.dataTransfer.files;
                document.getElementById('upload-form').submit();
            }
        });

        fileInput.addEventListener('change', function() {
            if (this.files.length) {
                document.getElementById('upload-form').submit();
            }
        });
    </script>
</body>
</html>"""


@app.get("/", response_class=HTMLResponse)
async def home():
    return HOME_PAGE


@app.post("/upload")
async def upload_avatar(file: UploadFile = File(...)):
    if not file.filename.lower().endswith('.svg'):
        return HTMLResponse(content="""
        <!DOCTYPE html>
        <html><head><title>Upload Error</title>
        <style>
            body { font-family: -apple-system, sans-serif; background: #f0f2f5; padding: 20px; }
            .card { background: #fff; border-radius: 12px; padding: 24px; max-width: 600px; margin: 40px auto; }
            .back { color: #1a73e8; text-decoration: none; font-weight: 500; }
            .error { color: #d93025; background: #fce8e6; border-radius: 8px; padding: 16px; margin-top: 12px; }
        </style>
        </head><body>
        <div class="card">
            <a href="/" class="back">&larr; Back to Home</a>
            <h2 style="color:#d93025;">Upload Failed</h2>
            <div class="error">Error: Only SVG files are accepted. Please upload a file with .svg extension.</div>
        </div>
        </body></html>""", status_code=400)

    svg_content = await file.read()

    try:
        # VULNERABILITY: XXE - XMLParser allows DTD loading, entity resolution, and network access
        parser = etree.XMLParser(load_dtd=True, resolve_entities=True, no_network=False)
        tree = etree.fromstring(svg_content, parser)

        width = tree.get('width', 'auto')
        height = tree.get('height', 'auto')
        viewbox = tree.get('viewBox', 'N/A')

        # Extract text content from parsed tree (entities are resolved here)
        parsed_texts = []
        for elem in tree.iter():
            if elem.text and elem.text.strip():
                parsed_texts.append(f"<{elem.tag}>: {elem.text.strip()}")
        parsed_summary = ' | '.join(parsed_texts) if parsed_texts else 'No text content found'

        svg_str = svg_content.decode('utf-8', errors='replace')

        result_html = f"""<!DOCTYPE html>
<html><head><title>Avatar Uploaded Successfully</title>
<style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f0f2f5; padding: 20px; color: #333; }}
    .card {{ background: #fff; border-radius: 12px; padding: 24px; max-width: 700px; margin: 40px auto; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }}
    .back {{ color: #1a73e8; text-decoration: none; font-weight: 500; }}
    .back:hover {{ text-decoration: underline; }}
    h2 {{ color: #333; margin-bottom: 16px; }}
    .success {{ background: #e6f4ea; color: #137333; padding: 12px 16px; border-radius: 8px; margin-bottom: 16px; }}
    .detail {{ padding: 10px 0; border-bottom: 1px solid #eee; }}
    .detail:last-child {{ border-bottom: none; }}
    .label {{ color: #666; font-size: 13px; text-transform: uppercase; letter-spacing: 0.5px; }}
    .value {{ color: #333; font-size: 16px; margin-top: 2px; word-break: break-all; }}
    .preview {{ background: #f8f9fa; border-radius: 8px; padding: 20px; margin-top: 16px; text-align: center; border: 1px solid #e0e0e0; }}
    .content {{ background: #f8f9fa; border-radius: 8px; padding: 16px; margin-top: 16px; border: 1px solid #e0e0e0; max-height: 300px; overflow: auto; }}
    .content pre {{ margin: 0; font-size: 12px; white-space: pre-wrap; word-break: break-all; }}
</style>
</head><body>
<div class="card">
    <a href="/" class="back">&larr; Upload Another</a>
    <div class="success">Avatar uploaded and processed successfully!</div>
    <h2>SVG Details</h2>
    <div class="detail">
        <div class="label">Filename</div>
        <div class="value">{file.filename}</div>
    </div>
    <div class="detail">
        <div class="label">Width</div>
        <div class="value">{width}</div>
    </div>
    <div class="detail">
        <div class="label">Height</div>
        <div class="value">{height}</div>
    </div>
    <div class="detail">
        <div class="label">ViewBox</div>
        <div class="value">{viewbox}</div>
    </div>
    <div class="detail">
        <div class="label">Size</div>
        <div class="value">{len(svg_content)} bytes</div>
    </div>
    <div class="detail">
        <div class="label">Parsed Text Content</div>
        <div class="value">{parsed_summary}</div>
    </div>
    <h2 style="margin-top: 20px;">Raw SVG Content</h2>
    <div class="content"><pre>{svg_str}</pre></div>
</div>
</body></html>"""
        return HTMLResponse(content=result_html)
    except Exception as e:
        error_html = f"""<!DOCTYPE html>
<html><head><title>Upload Error</title>
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
    <h2 style="color:#d93025;">Processing Error</h2>
    <div class="error">Error processing SVG: {str(e)}</div>
</div>
</body></html>"""
        return HTMLResponse(content=error_html, status_code=400)
