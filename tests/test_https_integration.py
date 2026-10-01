import json
import os
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from vaptkit.assessment import approval_template, assess
from vaptkit.report import generate


class Handler(BaseHTTPRequestHandler):
    def do_HEAD(self):
        self.server.seen.append((self.command, self.path, self.headers.get("Proxy-Authorization")))
        if self.path == "/denied":
            status = 403
        elif self.path == "/redirect":
            status = 302
        elif self.headers.get("Proxy-Authorization") != "Bearer integration-test-token":
            status = 401
        else:
            status = 200
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        self.send_header("Strict-Transport-Security", "max-age=31536000")
        self.send_header("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Set-Cookie", "private-session=DO_NOT_PERSIST")
        if status == 302:
            self.send_header("Location", "https://outside-scope.example.invalid/")
        self.end_headers()

    def log_message(self, *args):
        pass


@unittest.skipUnless(shutil.which("openssl"), "openssl is required for local TLS integration tests")
class HTTPSIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.directory.cleanup)
        root = Path(cls.directory.name)
        key, certificate = root / "key.pem", root / "certificate.pem"
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key), "-out", str(certificate), "-days", "1",
            "-subj", "/CN=staging.example.invalid",
            "-addext", "subjectAltName=DNS:staging.example.invalid",
        ], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, check=True)
        os.chmod(key, 0o600)
        server_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_tls.load_cert_chain(certificate, key)
        cls.client_tls = ssl.create_default_context(cafile=str(certificate))
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.server.socket = server_tls.wrap_socket(cls.server.socket, server_side=True)
        cls.server.seen = []
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

        def close_server():
            cls.server.shutdown()
            cls.server.server_close()
            cls.thread.join(timeout=5)

        cls.addClassCleanup(close_server)

    def test_tls_request_report_pipeline_and_access_failures(self):
        config = {
            "schema_version": 1, "project": "local-integration",
            "target": {"environment": "staging", "url": "https://staging.example.invalid",
                       "allowed_hosts": ["staging.example.invalid"], "verification": "pending"},
            "scope": {"api_prefixes": [], "excluded_prefixes": [], "roles": []},
            "credentials": {},
            "access": {"type": "bearer", "token_env": "VAPT_INTEGRATION_TOKEN",
                       "header": "Proxy-Authorization"},
        }
        now = datetime.now(timezone.utc)
        approval = approval_template(config)
        approval.update(
            approved_by="Local fixture owner", starts_at=(now - timedelta(minutes=1)).isoformat(),
            expires_at=(now + timedelta(minutes=5)).isoformat(),
        )
        real_connect = socket.create_connection

        def connect(address, timeout):
            self.assertEqual(address, ("8.8.8.8", 443))
            return real_connect(self.server.server_address, timeout=timeout)

        with patch("vaptkit.assessment.public_addresses", return_value=["8.8.8.8"]), patch(
            "vaptkit.assessment.socket.create_connection", side_effect=connect
        ), patch("vaptkit.assessment.ssl.create_default_context", return_value=self.client_tls):
            for path, token, expected in (
                ("/", "integration-test-token", 200),
                ("/", "wrong-token", 401),
                ("/denied", "integration-test-token", 403),
                ("/redirect", "integration-test-token", 302),
            ):
                with self.subTest(status=expected), tempfile.TemporaryDirectory() as directory, patch.dict(
                    os.environ, {"VAPT_INTEGRATION_TOKEN": token}
                ):
                    root = Path(directory)
                    approval["paths"] = [path]
                    before = len(self.server.seen)
                    record, code = assess(config, approval, root / "assessment")
                    self.assertEqual(len(self.server.seen), before + 1)
                    self.assertEqual(self.server.seen[-1][0], "HEAD")
                    result = json.loads(record.read_text())
                    self.assertEqual(result["observations"][0]["status"], expected)
                    self.assertEqual(code, 0 if expected == 200 else 1)
                    self.assertEqual(result["findings"], [])
                    self.assertNotIn(token, record.read_text())
                    self.assertNotIn("DO_NOT_PERSIST", record.read_text())
                    report = generate(record, root / "report", reviewed=True, html_only=True)
                    self.assertIn("Not tested", report.read_text())
                    if expected != 200:
                        self.assertIn("Not assessed (non-2xx response)", report.read_text())
