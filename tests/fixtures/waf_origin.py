"""Disposable synthetic origin, reachable only inside the lab's network namespace."""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def dispatch(self):
        path = urlsplit(self.path)
        query = parse_qs(path.query)
        key = query.get("key", [""])[0]
        if self.command == "POST":
            length = int(self.headers.get("Content-Length", "0"))
            if length > 4096:
                self.send_error(413)
                return
            self.rfile.read(length)
        if path.path == "/seen":
            value = {"seen": key in self.server.seen}
            status = 200
        elif path.path == "/ready":
            value, status = {"ready": True}, 200
        elif path.path in ("/echo", "/denied") and key:
            self.server.seen.add(key)
            value = {"marker": key}
            status = 403 if path.path == "/denied" else 200
        else:
            value, status = {"error": "Unknown fixture path"}, 404
        body = json.dumps(value).encode()
        self.send_response_only(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = dispatch
    do_POST = dispatch


if __name__ == "__main__":
    server = ThreadingHTTPServer(("127.0.0.1", 8081), Handler)
    server.seen = set()
    server.serve_forever()
