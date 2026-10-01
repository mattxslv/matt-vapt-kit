"""Opt-in release challenge. Locally authored, not an independent blind evaluation."""
import json
import shutil
import socket
import tempfile
import unittest
from contextlib import ExitStack
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from unittest.mock import patch

import test_https_integration
from vaptkit.report import generate, validate_result
from vaptkit.roles import role_outcome, run, template

HOST = "staging.example.invalid"
PATH = "/api/lead-evaluator/requirements"
MANIFEST = json.loads(Path(__file__).with_name("role_cases.json").read_text())
ENV = {
    "CHALLENGE_PROVIDER_EMAIL": "provider@example.invalid",
    "CHALLENGE_LEAD_EMAIL": "lead@example.invalid",
    "CHALLENGE_PASSWORD": "SYNTHETIC_CHALLENGE_PASSWORD",
}
DATA = {"data": [{"id": "SYNTHETIC_CHALLENGE_RECORD"}], "stats": {"total": 1}}


class ChallengeHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def send(self, status, body, content_type="application/json", headers=()):
        body = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response_only(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for name, value in headers:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        self.server.paths.append(self.path)
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        if self.path == "/api/auth/signout":
            self.send(200, {"success": True})
        elif self.path == "/api/auth/signin" and body["password"] == ENV["CHALLENGE_PASSWORD"]:
            lead = body["email"] == ENV["CHALLENGE_LEAD_EMAIL"]
            role = "lead-evaluator" if lead else "service-provider"
            self.send(200, {"user": {"email": body["email"], "user_type": role}}, headers=(
                ("Set-Cookie", f"auth-token={'lead' if lead else 'provider'}; Path=/; Secure; HttpOnly"),
                ("Set-Cookie", "session-bind=SYNTHETIC_CHALLENGE_BIND; Path=/; Secure; HttpOnly"),
            ))
        else:
            self.send(400, {"error": "Unexpected fixture request"})

    def do_GET(self):
        self.server.paths.append(self.path)
        if self.path != PATH:
            self.send(404, {"error": "Unlisted fixture path"})
            return
        cookie = self.headers.get("Cookie", "")
        mode = self.server.mode
        if "auth-token=lead;" in cookie:
            self.send(200, {"data": [], "stats": {}} if mode == "empty-control" else DATA)
            return
        if "auth-token=provider;" not in cookie:
            self.send(401, {"error": "Authentication required"})
            return
        self.server.attempt += 1
        if mode == "safe" or (mode == "inconsistent" and self.server.attempt > 1):
            self.send(403, {"error": "Role denied"})
        elif mode == "html-login":
            self.send(200, b"<html>Sign in</html>", "text/html")
        elif mode == "json-login":
            self.send(200, {"message": "Sign in"})
        elif mode == "error-envelope":
            self.send(200, {**DATA, "success": False})
        elif mode in ("empty", "empty-page"):
            self.send(200, {"data": [], "stats": {}, "next": "/unapproved/page/2"})
        elif mode == "expired":
            self.send(401, {"error": "Session expired"})
        elif mode == "gateway":
            self.send(403, b"<html>Gateway access denied</html>", "text/html")
        elif mode == "redirect":
            self.send(302, {}, headers=(("Location", "https://outside.example.invalid/"),))
        elif mode == "rate-limit":
            self.send(429, {"error": "Rate limited"})
        elif mode == "oversized":
            self.send(200, {**DATA, "padding": "x" * 70000})
        else:
            headers = (("Age", "120"),) if mode == "cached" else (
                (("X-Cache", "HIT"),) if mode == "cache-hit" else ()
            )
            self.send(200, {**DATA, "next": "/unapproved/page/2"} if mode == "page-bypass" else DATA,
                      headers=headers)


class RoleReleaseChallenge(unittest.TestCase):
    handler = ChallengeHandler

    @classmethod
    def setUpClass(cls):
        if not shutil.which("openssl"):
            raise RuntimeError("OpenSSL is required; the release challenge must not silently skip.")
        test_https_integration.HTTPSIntegrationTests.setUpClass.__func__(cls)

    def test_versioned_outcomes_over_loopback_https(self):
        config = {
            "schema_version": 1, "project": "release-challenge",
            "target": {"environment": "staging", "url": f"https://{HOST}",
                       "allowed_hosts": [HOST], "verification": "pending"},
            "scope": {"api_prefixes": ["/api/"], "excluded_prefixes": [],
                      "roles": ["service-provider", "lead-evaluator"]},
            "credentials": {},
            "role_testing": {
                "adapter": "dtap-cookie-v1",
                "accounts": [
                    {"id": "provider", "role": "service-provider", "email_env": "CHALLENGE_PROVIDER_EMAIL",
                     "password_env": "CHALLENGE_PASSWORD"},
                    {"id": "lead", "role": "lead-evaluator", "email_env": "CHALLENGE_LEAD_EMAIL",
                     "password_env": "CHALLENGE_PASSWORD"},
                ],
                "routes": [{"path": PATH, "allowed_roles": ["lead-evaluator"],
                            "response_shape": {"data": "array", "stats": "object"}}],
            },
        }
        approval = template(config)
        now = datetime.now(timezone.utc)
        approval.update(approved_by="Local release fixture", role_login=True,
                        starts_at=(now - timedelta(minutes=1)).isoformat(),
                        expires_at=(now + timedelta(minutes=5)).isoformat())
        real_connect = socket.create_connection
        def addresses(host):
            self.assertEqual(host, HOST, "Release challenge must not accept live targets")
            return ["8.8.8.8"]
        def connect(address, timeout):
            self.assertEqual(address, ("8.8.8.8", 443))
            return real_connect(self.server.server_address, timeout=timeout)

        counts = {"confirmed": 0, "denied": 0, "inconclusive": 0, "blocked": 0}
        self.assertEqual(MANIFEST["version"], 1)
        cases = MANIFEST["cases"]
        self.assertEqual(len(cases), 17)
        self.assertEqual(len({case["id"] for case in cases}), len(cases))
        with ExitStack() as stack:
            for mock in (
                patch.dict("os.environ", ENV),
                patch("vaptkit.assessment.public_addresses", side_effect=addresses),
                patch("vaptkit.assessment.socket.create_connection", side_effect=connect),
                patch("vaptkit.assessment.ssl.create_default_context", return_value=self.client_tls),
                patch("vaptkit.roles.time.sleep"),
            ):
                stack.enter_context(mock)
            root = Path(stack.enter_context(tempfile.TemporaryDirectory()))
            for case in cases:
                with self.subTest(case=case["id"]):
                    self.server.mode, self.server.attempt, self.server.paths = case["mode"], 0, []
                    output, code = run(config, approval, root / case["id"])
                    text = output.read_text()
                    result = json.loads(text)
                    validate_result(result)
                    records = result["role_observations"]
                    controls = {item["path"] for item in records if role_outcome(item, set()) == "allowed"}
                    provider = next(item for item in records if item["account"] == "provider")
                    outcome = role_outcome(provider, controls)
                    counts[outcome] += 1
                    self.assertEqual(outcome, case["outcome"])
                    self.assertEqual(result["status"], case["status"])
                    self.assertEqual(code, int(case["status"] == "incomplete"))
                    self.assertEqual(sum(f["verification"] == "confirmed" for f in result["findings"]),
                                     case["confirmed"])
                    self.assertTrue(set(self.server.paths) <= {
                        PATH, "/api/auth/signin", "/api/auth/signout",
                    })
                    self.assertLessEqual(len(self.server.paths), 8)
                    if outcome == "blocked":
                        self.assertEqual(self.server.paths[-1], PATH)
                        self.assertEqual(result["role_cleanup"][0]["status"], "unconfirmed")
                    report = generate(output, root / (case["id"] + "-report"), reviewed=True, html_only=True)
                    for sentinel in (*ENV.values(), "SYNTHETIC_CHALLENGE_RECORD", "SYNTHETIC_CHALLENGE_BIND"):
                        self.assertNotIn(sentinel, text + report.read_text())
            self.assertEqual(counts, {"confirmed": 2, "denied": 1, "inconclusive": 10, "blocked": 4})
            with self.assertRaises(AssertionError):
                addresses("test.dtap.dict.gov.ph")
        print("\nRelease role challenge v1: " + json.dumps(counts, sort_keys=True))
