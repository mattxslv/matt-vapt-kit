"""Local-only HTTPS accuracy corpus. Passing this corpus is not a production accuracy guarantee."""
import json
import shutil
import socket
import tempfile
import unittest
from contextlib import ExitStack
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from unittest.mock import patch

from test_assessment import approved
from test_headers import STRONG
import test_https_integration
from test_roles import Application, ENV, approval_for, configuration
from vaptkit.assessment import assess, findings_for, observe, request
from vaptkit.report import generate, validate_result
from vaptkit.roles import run as run_roles


HEADER_CASES = [
    ("hsts_present", {"strict-transport-security": None}),
    ("csp_present", {"content-security-policy": None}),
    ("nosniff", {"x-content-type-options": "invalid"}),
    ("frame_policy_present", {"content-security-policy": "default-src 'self'"}),
    ("hsts_strong", {"strict-transport-security": "max-age=15551999"}),
    ("csp_script_strong", {"content-security-policy": "default-src 'self' 'unsafe-inline'; frame-ancestors 'none'"}),
    ("frame_policy_strong", {"content-security-policy": "default-src 'self'; frame-ancestors *"}),
    ("referrer_policy_safe", {"referrer-policy": "unsafe-url"}),
    ("cookies_secure", {"set-cookie": "auth-token=fixture; HttpOnly"}),
    ("session_cookies_httponly", {"set-cookie": "auth-token=fixture; Secure"}),
    ("no_version_disclosure", {"server": "fixture/1.2"}),
]
EDGE_CASES = [
    ("hsts_strong", {"strict-transport-security": "max-age=31536000oops"}, True),
    ("hsts_strong", {"strict-transport-security": "x-max-age=31536000"}, True),
    ("hsts_strong", {"strict-transport-security": "max-age=15552000"}, False),
    ("csp_script_strong", {"content-security-policy": "default-src https: 'strict-dynamic'"}, True),
    ("csp_script_strong", {"content-security-policy": "default-src 'self' 'nonce-' 'unsafe-inline'"}, True),
    ("csp_script_strong", {"content-security-policy": "default-src 'self'; script-src-elem *"}, True),
    ("csp_script_strong", {"content-security-policy": "default-src 'self'; script-src-attr 'unsafe-inline'"}, True),
    ("csp_script_strong", {"content-security-policy": "default-src 'self' 'unsafe-inline', default-src 'none'"}, False),
    ("csp_script_strong", {"content-security-policy": ["default-src 'self' 'unsafe-inline'", "default-src 'none'"]}, False),
    ("referrer_policy_safe", {"referrer-policy": "unsafe-url, unknown-policy"}, True),
    ("referrer_policy_safe", {"referrer-policy": "unsafe-url, no-referrer"}, False),
]


class BenchmarkHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def emit(self, status, headers, body=b""):
        self.send_response_only(status)
        self.send_header("Content-Length", str(len(body)))
        for name, values in headers.items():
            for value in values if isinstance(values, list) else [values]:
                self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def dispatch(self):
        if self.path.startswith("/headers/"):
            changes = self.server.header_changes
            headers = dict(STRONG)
            for key, value in changes.items():
                if value is None:
                    headers.pop(key, None)
                else:
                    headers[key] = value
            self.emit(200, headers)
            return
        if self.path == "/large":
            self.emit(200, {"content-type": "text/plain"}, b"x" * 4096)
            return
        if self.path.startswith("/api/auth/") or self.path == "/api/lead-evaluator/requirements":
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length) if length else None
            status, headers, data = self.server.application(
                "staging.example.invalid", self.command, self.path,
                headers=dict(self.headers), body=body,
            )
            self.emit(status, headers, data)
            return
        mode = self.server.exposure_mode
        headers = dict(STRONG)
        if self.path == "/":
            self.emit(200, headers, b'<script src="/_next/static/fixture.js"></script>')
        elif mode == "catchall":
            self.emit(200, {"content-type": "text/html"}, b"<html>Catchall fixture</html>")
        else:
            exposed = {
                "/.env": ("text/plain", b"SYNTHETIC_SETTING=value"),
                "/.git/HEAD": ("text/plain", b"ref: refs/heads/fixture"),
                "/api/health": ("application/json", b'{"version":"fixture","database":"synthetic"}'),
                "/openapi.json": ("application/json", b'{"openapi":"3.0.0","paths":{}}'),
                "/_next/static/fixture.js.map": ("application/json", b'{"sources":[],"version":3,"mappings":""}'),
            }
            if mode == "weak" and self.path in exposed:
                content_type, body = exposed[self.path]
                self.emit(200, {"content-type": content_type}, body)
            elif mode == "safe" and self.path == "/api/health":
                self.emit(200, {"content-type": "application/json"}, b'{"status":"ok"}')
            else:
                self.emit(404, {"content-type": "text/plain"}, b"Not found")

    do_HEAD = dispatch
    do_GET = dispatch
    do_POST = dispatch


@unittest.skipUnless(shutil.which("openssl"), "openssl is required for the local TLS accuracy benchmark")
class AccuracyBenchmark(unittest.TestCase):
    handler = BenchmarkHandler
    setUpClass = classmethod(test_https_integration.HTTPSIntegrationTests.setUpClass.__func__)

    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        real_connect = socket.create_connection

        def connect(address, timeout):
            self.assertEqual(address, ("8.8.8.8", 443))
            return real_connect(self.server.server_address, timeout=timeout)

        for mock in (
            patch("vaptkit.assessment.public_addresses", return_value=["8.8.8.8"]),
            patch("vaptkit.assessment.socket.create_connection", side_effect=connect),
            patch("vaptkit.assessment.ssl.create_default_context", return_value=self.client_tls),
            patch("vaptkit.assessment.time.sleep"),
            patch("vaptkit.roles.time.sleep"),
            # Passive recon (DNS hygiene, crt.sh subdomains) talks to real third-party services,
            # not the loopback test server this benchmark otherwise pins every connection to.
            patch("vaptkit.recon.dns_hygiene", return_value={"spf_present": False, "dmarc_present": False,
                                                             "dmarc_policy": None, "dkim_selectors_found": []}),
            patch("vaptkit.recon.subdomains", return_value=[]),
            patch("vaptkit.recon.scan_ports", return_value=[]),
            patch("vaptkit.recon.tls_hygiene", return_value={
                "legacy_protocols_supported": [], "negotiated_cipher": None, "cert_days_to_expiry": None}),
        ):
            self.stack.enter_context(mock)

    def test_header_confusion_matrix_over_https(self):
        counts = {key: {"tp": 0, "fp": 0, "tn": 0, "fn": 0} for key, _ in HEADER_CASES}
        cases = [(key, {}, False) for key, _ in HEADER_CASES]
        cases += [(key, changes, True) for key, changes in HEADER_CASES] + EDGE_CASES
        for index, (key, changes, expected) in enumerate(cases):
            self.server.header_changes = changes
            item = observe("staging.example.invalid", f"/headers/{index}")
            detected = key in {finding["check_id"] for finding in findings_for(item)}
            counts[key]["tp" if expected and detected else "fn" if expected else "fp" if detected else "tn"] += 1
        print("\nLocal HTTPS header benchmark: " + json.dumps(counts, sort_keys=True))
        self.assertEqual(sum(item["fp"] for item in counts.values()), 0, counts)
        self.assertEqual(sum(item["fn"] for item in counts.values()), 0, counts)
        self.assertTrue(all(item["tp"] >= 1 and item["tn"] >= 1 for item in counts.values()))

    def test_exposure_confusion_matrix_and_retest_over_https(self):
        config = configuration()
        config["target"]["url"] = "https://staging.example.invalid"
        config["target"]["allowed_hosts"] = ["staging.example.invalid"]
        approval = approved(config)
        approval["exposure_checks"] = True
        expected = {"/.env", "/.git/HEAD", "/api/health", "/openapi.json", "/_next/static/fixture.js.map"}
        baseline = None
        counts = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for mode in ("weak", "safe", "catchall"):
                self.server.exposure_mode = mode
                output, code = assess(config, approval, root / mode, baseline if mode == "safe" else None)
                result = json.loads(output.read_text())
                validate_result(result)
                self.assertEqual(code, 0, result["errors"])
                detected = {item["path"] for item in result["findings"]}
                for path in expected:
                    actual, found = mode == "weak", path in detected
                    counts["tp" if actual and found else "fn" if actual else "fp" if found else "tn"] += 1
                self.assertFalse(detected - expected)
                if mode == "weak":
                    baseline = result
                    self.assertEqual({item["path"] for item in result["findings"] if item["verification"] == "confirmed"},
                                     {"/.env", "/.git/HEAD", "/_next/static/fixture.js.map"})
                if mode == "safe":
                    rows = {item["path"]: item["status"] for item in result["retest"]}
                    self.assertEqual(rows["/.env"], "resolved")
                    self.assertEqual(rows["/api/health"], "not_rechecked")
                report = generate(output, root / f"{mode}-report", reviewed=True, html_only=True)
                self.assertIn("Public Exposure Checks", report.read_text())
                self.assertNotIn("SYNTHETIC_SETTING", output.read_text())
        print("\nLocal HTTPS exposure benchmark: " + json.dumps(counts, sort_keys=True))
        self.assertEqual(counts, {"tp": 5, "fp": 0, "tn": 10, "fn": 0})

    def test_role_confirmation_confusion_matrix_over_https(self):
        config = configuration()
        config["target"]["url"] = "https://staging.example.invalid"
        config["target"]["allowed_hosts"] = ["staging.example.invalid"]
        counts = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
        with tempfile.TemporaryDirectory() as directory, patch.dict("os.environ", ENV):
            for mode in ("safe", "weak", "catchall"):
                self.server.application = Application(vulnerable=mode == "weak", catchall=mode == "catchall")
                output, code = run_roles(config, approval_for(config), Path(directory) / mode)
                result = json.loads(output.read_text())
                validate_result(result)
                self.assertEqual(code, 1 if mode == "catchall" else 0, result["errors"])
                confirmed = {item["title"] for item in result["findings"] if item["verification"] == "confirmed"}
                for account in ("anonymous", "service-provider"):
                    actual = mode == "weak"
                    found = f"Unexpected endpoint access for {account}" in confirmed
                    counts["tp" if actual and found else "fn" if actual else "fp" if found else "tn"] += 1
                generate(output, Path(directory) / f"{mode}-report", reviewed=True, html_only=True)
        print("\nLocal HTTPS role benchmark: " + json.dumps(counts, sort_keys=True))
        self.assertEqual(counts, {"tp": 2, "fp": 0, "tn": 4, "fn": 0})

    def test_body_limit_enforced_when_server_ignores_range(self):
        status, _, body = request("staging.example.invalid", "GET", "/large",
                                  headers={"Range": "bytes=0-2047"}, body_limit=2048)
        self.assertEqual(status, 200)
        self.assertEqual(len(body), 2048)
