"""Intentionally vulnerable, loopback-only test pages. Never deploy this fixture."""
import html
import json
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlsplit


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def send(self, body, status=200, *, csp=False, content_type="text/html"):
        body = body.encode()
        self.send_response_only(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if csp:
            self.send_header("Content-Security-Policy",
                             "script-src 'nonce-fixture-bootstrap'; object-src 'none'; base-uri 'none'")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path != "/store":
            self.send("Not found", 404)
            return
        length = int(self.headers.get("Content-Length", "0"))
        if not 0 < length <= 2048:
            self.send("Invalid fixture input", 400)
            return
        data = json.loads(self.rfile.read(length))
        key = str(len(self.server.records) + 1)
        self.server.records[key] = data["value"]
        self.send(json.dumps({"id": key}), content_type="application/json")

    def do_GET(self):
        parsed = urlsplit(self.path)
        query = parse_qs(parsed.query)
        if parsed.path == "/control":
            self.send("<html><body>" + (
                "" if "broken" in query else "<script>window.__mvk_control__ = true;</script>"
            ) + "</body></html>")
            return
        if parsed.path != "/view":
            self.send("Not found", 404)
            return
        kind = query.get("kind", ["reflected"])[0]
        mode = query.get("mode", ["escaped"])[0]
        value = query.get("value", [""])[0]
        if mode == "denied":
            self.send("<html>Login required</html>", 401)
            return
        if mode == "json":
            self.send(json.dumps({"value": value}), content_type="application/json")
            return
        if kind == "stored":
            value = self.server.records[query["id"][0]]
        if kind == "dom":
            sink = "textContent" if mode == "escaped" else "innerHTML"
            body = (
                '<div id="slot"></div><script nonce="fixture-bootstrap">'
                "const value = new URL(location.href).searchParams.get('value') || '';"
                f"document.getElementById('slot').{sink} = value;</script>"
            )
        else:
            body = html.escape(value) if mode == "escaped" else value
        self.send("<html><body>" + body + "</body></html>", csp=mode == "csp")
