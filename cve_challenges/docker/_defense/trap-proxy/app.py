"""Trap defense proxy — injects anti-automation behaviors.

Behaviors:
- Slow response (random 2-10s delay on 30% of requests)
- Infinite data stream (Content-Length: 99999999 but never completes)
- Connection reset (randomly drops connections)
"""
import http.server
import random
import socketserver
import time
import urllib.request

BACKEND = "http://web:80"
LISTEN_PORT = 8080
SLOW_PROBABILITY = 0.3
DROP_PROBABILITY = 0.1


class TrapHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self._handle()
    def do_POST(self):
        self._handle()
    def do_PUT(self):
        self._handle()

    def _handle(self):
        # Connection trap: randomly drop
        if random.random() < DROP_PROBABILITY:
            self.connection.close()
            return

        # Slow response trap
        if random.random() < SLOW_PROBABILITY:
            delay = random.uniform(2, 10)
            time.sleep(delay)

        try:
            req = urllib.request.Request(
                f"{BACKEND}{self.path}",
                data=self.rfile.read(int(self.headers.get("Content-Length", 0)))
                if self.command == "POST" else None,
                headers={k: v for k, v in self.headers.items() if k.lower() not in ("host",)},
                method=self.command,
            )
            resp = urllib.request.urlopen(req, timeout=30)
            self.send_response(resp.status)
            for k, v in resp.headers.items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(resp.read())
        except Exception:
            self.send_response(502)
            self.end_headers()


if __name__ == "__main__":
    with socketserver.ThreadingTCPServer(("", LISTEN_PORT), TrapHandler) as httpd:
        httpd.serve_forever()
