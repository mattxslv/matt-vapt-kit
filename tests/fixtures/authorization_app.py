"""Synthetic application under test. Never imports the toolkit's detection logic."""
import copy
import json
import secrets
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler

USERS = {"alice": "evaluator", "bob": "evaluator", "charlie": "lead-evaluator", "dana": "director"}
MODES = {
    "safe", "read-bypass", "write-bypass", "skip-review", "self-approve", "replay",
    "denial-with-write", "fake-success", "wrong-object", "wrong-actor", "error-body-leak",
    "metadata-only", "login-page", "unavailable", "broken-json", "oversized", "missing-control",
}


class Application:
    def __init__(self, mode="safe"):
        if mode not in MODES:
            raise ValueError("Unknown fixture mode")
        self.mode = mode
        self.sessions = {}
        self.documents = {}
        self.requests = []
        self.revocations = 0

    def seed(self, identifier, owner, phase="draft", shared=()):
        self.documents[identifier] = {
            "id": identifier, "owner": owner, "phase": phase, "revision": 0,
            "private_note": f"SYNTHETIC_PRIVATE_{identifier}",
            "text": "Synthetic document", "shared": list(shared),
            "last_actor": None, "last_action": None,
        }

    def allowed_read(self, user, document):
        return (user == document["owner"] or user in document["shared"]
                or USERS.get(user) in ("lead-evaluator", "director"))

    def handle(self, method, path, headers, body):
        cookie = SimpleCookie()
        cookie.load(headers.get("Cookie", ""))
        token = cookie["fixture-session"].value if "fixture-session" in cookie else ""
        user = self.sessions.get(token)
        self.requests.append((method, path, user))
        if path == "/login" and method == "POST":
            data = json.loads(body)
            if data.get("user") not in USERS or data.get("password") != "synthetic-only":
                return 401, {}, {"error": "Invalid fixture login"}
            token = secrets.token_hex(16)
            self.sessions[token] = data["user"]
            return 200, {"Set-Cookie": f"fixture-session={token}; Path=/; Secure; HttpOnly"}, {
                "user": data["user"], "role": USERS[data["user"]],
            }
        if path == "/logout" and method == "POST":
            if token in self.sessions:
                del self.sessions[token]
                self.revocations += 1
            return 200, {}, {"success": True}
        parts = path.strip("/").split("/")
        if len(parts) not in (2, 3) or parts[0] != "documents":
            return 404, {}, {"error": "Not found"}
        document = self.documents.get(parts[1])
        if document is None:
            return 404, {}, {"error": "Not found"}
        if method == "GET" and len(parts) == 2:
            allowed = self.allowed_read(user, document)
            if self.mode == "missing-control" and allowed:
                return 503, {}, {"error": "Unavailable"}
            if allowed:
                return 200, {}, {"data": copy.deepcopy(document)}
            if self.mode in ("read-bypass", "error-body-leak"):
                return 403 if self.mode == "error-body-leak" else 200, {}, {"data": copy.deepcopy(document)}
            if self.mode == "wrong-object":
                other = next((item for item in self.documents.values() if item["owner"] == user), None)
                return 200, {}, {"data": copy.deepcopy(other)}
            if self.mode == "metadata-only":
                return 200, {}, {"data": {"id": document["id"], "owner": document["owner"]}}
            if self.mode == "login-page":
                return 200, {"Content-Type": "text/html"}, b"<html>Sign in</html>"
            if self.mode == "unavailable":
                return 503, {}, {"error": "Unavailable"}
            if self.mode == "broken-json":
                return 200, {}, b'{"data":'
            if self.mode == "oversized":
                return 200, {}, b'{"padding":"' + b"x" * 70000 + b'"}'
            return 403 if user else 401, {}, {"error": "Access denied"}
        if method != "POST" or len(parts) != 3:
            return 405, {}, {"error": "Method not allowed"}
        action = parts[2]
        transitions = {
            "edit": ("draft", "draft"), "submit": ("draft", "submitted"),
            "review": ("submitted", "reviewed"), "approve": ("reviewed", "approved"),
        }
        if action not in transitions:
            return 404, {}, {"error": "Unknown action"}
        start, finish = transitions[action]
        role = USERS.get(user)
        owner = user == document["owner"]
        permission = (owner if action in ("edit", "submit") else
                      role == ("lead-evaluator" if action == "review" else "director") and not owner)
        correct_phase = document["phase"] == start
        allowed = permission and correct_phase
        bypass = (
            self.mode in ("write-bypass", "denial-with-write") and action == "edit" and correct_phase and user
            or self.mode == "skip-review" and action == "approve" and role == "director" and not owner
            or self.mode == "self-approve" and action == "approve" and role == "director" and correct_phase
            or self.mode == "replay" and action == "approve" and permission and document["phase"] == "approved"
            or self.mode == "wrong-actor" and action == "edit"
        )
        if not allowed and not bypass:
            if self.mode == "fake-success":
                return 200, {}, {"success": True}
            return 403 if not permission else 409, {}, {"error": "Forbidden transition"}
        document["phase"] = finish
        document["revision"] += 1
        document["last_actor"] = "unrelated-actor" if self.mode == "wrong-actor" and not allowed else user
        document["last_action"] = action
        if action == "edit":
            document["text"] = "Edited synthetic document"
        return 403 if self.mode == "denial-with-write" and not allowed else 200, {}, {"success": True}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def dispatch(self):
        size = int(self.headers.get("Content-Length", "0"))
        if size > 4096:
            self.send_error(413)
            return
        status, headers, value = self.server.application.handle(
            self.command, self.path, self.headers, self.rfile.read(size),
        )
        body = value if isinstance(value, bytes) else json.dumps(value).encode()
        self.send_response_only(status)
        self.send_header("Content-Type", headers.pop("Content-Type", "application/json"))
        self.send_header("Content-Length", str(len(body)))
        for key, val in headers.items():
            self.send_header(key, val)
        self.end_headers()
        self.wfile.write(body)

    do_GET = dispatch
    do_POST = dispatch
