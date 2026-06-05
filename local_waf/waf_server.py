"""Local ModSecurity-style WAF — no Docker required.

Mimics ModSecurity + OWASP CRS behavior:
- Blocks SQLi patterns (UNION SELECT, ' OR 1=1, etc.)
- Blocks XSS patterns (<script>, onerror=, etc.)
- Blocks CMDi patterns (;id, |cat, $(whoami), etc.)
- Adds ModSecurity fingerprint headers
- Returns 403 with ModSecurity block page

Usage:
    python3 benchmarks/local_waf/waf_server.py 8001 8002
    # Starts WAF on :8001, forwarding to backend on :8002
"""

from __future__ import annotations

import argparse
import re
import sys
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Thread
from urllib.request import urlopen, Request


class WAFHandler(BaseHTTPRequestHandler):
    """ModSecurity-style WAF forward proxy."""

    backend_url: str = "http://localhost:8000"
    block_counter: int = 0

    # ── WAF Rule Set (OWASP CRS style) ──────────────────────────

    BLOCK_RULES = [
        # SQLi
        (re.compile(r"(?i)(union\s+select|union\s+all\s+select)"), "942100", "SQLi: UNION SELECT"),
        (re.compile(r"(?i)('\)\s*or\s*'.*'='|'\s+or\s+1\s*=\s*1|'\s+or\s+'1'\s*=\s*'1)"), "942110", "SQLi: OR injection"),
        (re.compile(r"(?i)(select\s+.*\s+from\s+|insert\s+into\s+|update\s+.*\s+set\s+|delete\s+from\s+)"), "942120", "SQLi: DML keywords"),
        (re.compile(r"(?i)(information_schema|mysql\.|sqlite_master|pg_catalog)"), "942130", "SQLi: schema probing"),
        (re.compile(r"(?i)(--[^\n]*$|#.*$|/\*.*\*/)"), "942140", "SQLi: comment sequence"),

        # XSS
        (re.compile(r"(?i)(<script\b|</script>)"), "941100", "XSS: script tag"),
        (re.compile(r"(?i)(onerror\s*=|onload\s*=|onclick\s*=|onmouseover\s*=)"), "941110", "XSS: event handler"),
        (re.compile(r"(?i)(<img\b|<svg\b|<iframe\b|<object\b|<embed\b)"), "941120", "XSS: dangerous tag"),
        (re.compile(r"(?i)(javascript\s*:|data\s*:.*base64)"), "941130", "XSS: protocol"),
        (re.compile(r"(?i)(alert\s*\(|prompt\s*\(|confirm\s*\()"), "941140", "XSS: JS function"),

        # CMDi
        (re.compile(r"(?i)(;\s*(id|ls|cat|whoami|pwd|uname|ifconfig|ipconfig|netstat|ps\b|wget\b|curl\b))"), "932100", "CMDi: semicolon"),
        (re.compile(r"(?i)(\|\s*(id|ls|cat|whoami|nc\b|bash\b|sh\b))"), "932110", "CMDi: pipe"),
        (re.compile(r"(?i)(`[^`]+`)"), "932120", "CMDi: backtick"),
        (re.compile(r"(?i)(\$\(.+?\))"), "932130", "CMDi: dollar subshell"),

        # Path traversal / LFI
        (re.compile(r"(?i)(\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e/)"), "930100", "LFI: path traversal"),
        (re.compile(r"(?i)(/etc/passwd|/etc/shadow|/proc/self|C:\\\\Windows)"), "930110", "LFI: system file"),

        # General attacks
        (re.compile(r"(?i)(sleep\s*\(\s*\d+\s*\)|benchmark\s*\(|pg_sleep\s*\()"), "942160", "SQLi: time-based"),
        (re.compile(r"(?i)(0x[0-9a-f]{8,})"), "942200", "SQLi: hex encoding"),
    ]

    def do_GET(self):
        self._proxy("GET")

    def do_POST(self):
        self._proxy("POST")

    def _proxy(self, method: str):
        # Read request body for POST
        body = b""
        if method == "POST":
            length = int(self.headers.get("Content-Length", 0))
            if length > 0:
                body = self.rfile.read(length)

        # Build full request data for WAF inspection
        request_data = self.path + " " + body.decode("utf-8", errors="replace")
        for k, v in self.headers.items():
            request_data += f" {k}:{v}"

        # ── WAF Inspection ──────────────────────────────────
        for pattern, rule_id, rule_msg in self.BLOCK_RULES:
            if pattern.search(request_data):
                self.block_counter += 1
                self._send_block(rule_id, rule_msg, pattern.pattern[:60])
                return

        # ── Forward to backend ──────────────────────────────
        backend_url = f"{self.backend_url}{self.path}"
        try:
            req = Request(
                backend_url,
                data=body if method == "POST" else None,
                headers={k: v for k, v in self.headers.items()
                         if k.lower() not in ("host", "content-length")},
                method=method,
            )
            resp = urlopen(req, timeout=30)
            resp_body = resp.read()

            self.send_response(resp.status)
            for k, v in resp.getheaders():
                if k.lower() not in ("transfer-encoding", "connection"):
                    self.send_header(k, v)
            # Add ModSecurity fingerprint
            self.send_header("Server", "Apache/2.4.41 (Ubuntu)")
            self.send_header("X-ModSecurity", "ModSecurity v3.0.8 (OWASP CRS 3.3.2)")
            self.end_headers()
            self.wfile.write(resp_body)

        except Exception as e:
            self.send_response(502)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(f"Backend error: {e}".encode())

    def _send_block(self, rule_id: str, rule_msg: str, pattern: str):
        """Send a ModSecurity-style block page."""
        body = f"""<!DOCTYPE html>
<html><head><title>403 Forbidden</title></head>
<body>
<h1>403 Forbidden</h1>
<p>Request blocked by ModSecurity (OWASP CRS).</p>
<p>Rule: {rule_id} — {rule_msg}</p>
<hr>
<address>Apache/2.4.41 (Ubuntu) ModSecurity/3.0.8 Server at localhost</address>
</body></html>"""
        body_bytes = body.encode("utf-8")
        self.send_response(403)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body_bytes)))
        self.send_header("Server", "Apache/2.4.41 (Ubuntu)")
        self.send_header("X-ModSecurity", "ModSecurity v3.0.8 (OWASP CRS 3.3.2)")
        self.end_headers()
        self.wfile.write(body_bytes)

    def log_message(self, format, *args):
        pass


def start_waf(listen_port: int, backend_port: int) -> HTTPServer:
    """Start WAF proxy and return server handle."""
    WAFHandler.backend_url = f"http://localhost:{backend_port}"
    server = HTTPServer(("", listen_port), WAFHandler)
    t = Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Local ModSecurity-style WAF")
    parser.add_argument("listen_port", type=int, help="WAF listen port")
    parser.add_argument("backend_port", type=int, help="Backend port to protect")
    args = parser.parse_args()

    WAFHandler.backend_url = f"http://localhost:{args.backend_port}"
    print(f"WAF listening on :{args.listen_port} → backend :{args.backend_port}")
    print(f"Rules loaded: {len(WAFHandler.BLOCK_RULES)}")
    HTTPServer(("", args.listen_port), WAFHandler).serve_forever()
