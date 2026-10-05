"""A tiny, local, intentionally-vulnerable HTTP target for scanner tests.

Runs on localhost in a background thread. It deliberately implements a few
vulnerable behaviors AND several benign-but-tricky behaviors (generic 500, WAF
block, rate limit, auth redirect, dynamic content) so the false-positive
regression suite can prove the validation engine does not over-claim.

Nothing here reaches the internet; it exists purely for deterministic testing.
"""
from __future__ import annotations

import html
import random
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # silence
        pass

    def _send(self, code: int, body: str, headers: dict | None = None):
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        params = {k: v[0] for k, v in parse_qs(parsed.query).items()}

        if path == "/reflect":
            q = params.get("q", "")
            # VULNERABLE: reflects input unescaped into the HTML body
            self._send(200, f"<html><body><h1>Search</h1><div>{q}</div></body></html>")
        elif path == "/reflect_safe":
            q = params.get("q", "")
            self._send(200, f"<html><body><div>{html.escape(q)}</div></body></html>")
        elif path == "/search":
            q = params.get("q", "")
            if "'" in q and "1=1" not in q and "1=2" not in q:
                # error-based signal
                self._send(500, "You have an error in your SQL syntax; check the manual")
            elif "1=2" in q:
                # FALSE condition -> empty result set (diverges from baseline)
                self._send(200, "<html><body>No products found.</body></html>")
            else:
                # baseline / TRUE condition -> full list
                self._send(200, "<html><body>Products: apple banana cherry date elderberry</body></html>")
        elif path == "/redirect":
            url = params.get("url", "/")
            self._send(302, "", {"Location": url})
        elif path == "/redirect_safe":
            self._send(302, "", {"Location": "/account"})
        elif path == "/error500":
            self._send(500, "<html><body>Internal Server Error</body></html>")
        elif path == "/waf":
            self._send(403, "<html><body>Attention Required! Cloudflare has blocked your request.</body></html>")
        elif path == "/ratelimit":
            self._send(429, "<html><body>Too Many Requests - rate limit exceeded</body></html>")
        elif path == "/login_redirect":
            self._send(302, "", {"Location": "/login?next=/private"})
        elif path == "/dynamic":
            token = random.randint(0, 10_000_000)
            self._send(200, f"<html><body>Session {token} at row {random.random()}</body></html>")
        elif path == "/headers_missing":
            self._send(200, "<html><body>no security headers here</body></html>")
        elif path == "/headers_present":
            self._send(200, "<html><body>secured</body></html>", {
                "Content-Security-Policy": "default-src 'self'",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Strict-Transport-Security": "max-age=63072000",
                "Referrer-Policy": "no-referrer",
            })
        else:
            self._send(200, "<html><body>home</body></html>")


class MockTarget:
    def __init__(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def base_url(self) -> str:
        host, port = self.server.server_address
        return f"http://{host}:{port}"

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()
