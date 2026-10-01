import copy
import json
import socket
import ssl
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

from vaptkit.assessment import (
    access_headers, approval_template, assess, digest, findings_for, load_json,
    observe, remaining_timeout, validate_approval,
)
from vaptkit.config import load_config
from vaptkit.process import ToolError
from vaptkit.report import validate_result

ROOT = Path(__file__).resolve().parents[1]


def approved(config):
    now = datetime.now(timezone.utc)
    approval = approval_template(config)
    approval.update(
        approved_by="Synthetic test owner",
        starts_at=(now - timedelta(minutes=1)).isoformat(),
        expires_at=(now + timedelta(minutes=30)).isoformat(),
    )
    return approval


def observation(path="/", status=200, protected=False):
    return {
        "path": path, "method": "HEAD", "status": status,
        "checks": {
            "html_response": True, "hsts_present": protected, "csp_present": protected,
            "nosniff": protected, "frame_policy_present": protected,
        },
    }


class ScopeTests(unittest.TestCase):
    def setUp(self):
        self.config = load_config(ROOT / "projects/pemedes.vapt.yml")
        self.approval = approved(self.config)

    def test_valid_scope(self):
        validate_approval(self.config, self.approval)
        self.assertEqual(self.approval["config_sha256"], digest(self.config))

    def test_invalid_scopes(self):
        cases = [
            {"method": "GET"}, {"project": "another"}, {"approved_by": ""},
            {"config_sha256": "0" * 64}, {"paths": []}, {"paths": ["/"] * 11},
            {"paths": ["/", "/"]}, {"paths": [None]}, {"paths": ["/api/admin/export"]},
            {"paths": ["//another.host"]}, {"paths": ["/x?secret=x"]},
            {"paths": ["/%2fadmin"]}, {"paths": ["/a/../admin"]}, {"paths": ["/x\n"]},
            {"paths": ["/caf\u00e9"]}, {"paths": ["/\x7f"]},
            {"interval_seconds": 0}, {"interval_seconds": True}, {"interval_seconds": float("nan")},
            {"request_timeout_seconds": 0}, {"request_timeout_seconds": 61},
            {"request_timeout_seconds": True}, {"request_timeout_seconds": float("nan")},
            {"expires_at": "2000-01-01T00:00:00Z"}, {"starts_at": "2100-01-01T00:00:00Z"},
            {"starts_at": "2026-01-01"}, {"unexpected": True},
        ]
        for change in cases:
            with self.subTest(change=change):
                approval = dict(self.approval, **change)
                with self.assertRaises(ToolError):
                    validate_approval(self.config, approval)

    def test_no_traffic_before_scope_approval(self):
        with tempfile.TemporaryDirectory() as directory, patch("vaptkit.assessment.observe") as request:
            with self.assertRaises(ToolError):
                assess(self.config, approval_template(self.config), Path(directory) / "out")
            request.assert_not_called()

    def test_results_no_leak_assurance(self):
        with tempfile.TemporaryDirectory() as directory, patch(
            "vaptkit.assessment.observe", return_value=observation()
        ):
            output, code = assess(self.config, self.approval, Path(directory) / "out")
            result = json.loads(output.read_text())
            validate_result(result)
            self.assertEqual(code, 0)
            self.assertEqual(len(result["findings"]), 4)
            self.assertEqual(result["coverage"]["data_exposure"], "not_tested")
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertEqual(output.parent.stat().st_mode & 0o777, 0o700)

    def test_stop_on_blocking_status(self):
        for status in (401, 403, 429, 500):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as directory, patch(
                "vaptkit.assessment.observe", return_value=observation(status=status)
            ) as request:
                self.approval["paths"] = ["/", "/about"]
                output, code = assess(self.config, self.approval, Path(directory) / "out")
                self.assertEqual(code, 1)
                self.assertEqual(request.call_count, 1)
                self.assertEqual(json.loads(output.read_text())["status"], "incomplete")

    def test_transport_error_is_not_clean_result(self):
        with tempfile.TemporaryDirectory() as directory, patch(
            "vaptkit.assessment.observe", side_effect=socket.timeout("PRIVATE_SENTINEL")
        ):
            output, code = assess(self.config, self.approval, Path(directory) / "out")
            self.assertEqual(code, 1)
            self.assertNotIn("PRIVATE_SENTINEL", output.read_text())

    def test_redirect_stops_further_requests(self):
        self.approval["paths"] = ["/", "/another"]
        with tempfile.TemporaryDirectory() as directory, patch(
            "vaptkit.assessment.observe", return_value=observation(status=302)
        ) as request:
            output, code = assess(self.config, self.approval, Path(directory) / "out")
            self.assertEqual(code, 1)
            self.assertEqual(request.call_count, 1)
            result = json.loads(output.read_text())
            self.assertIn("redirect not followed", result["errors"][0]["message"])
            self.assertEqual(result["findings"], [])

    def test_distinct_failure_diagnostics_without_raw_exception(self):
        cases = [
            (socket.gaierror("PRIVATE_SENTINEL"), "DNS"),
            (socket.timeout("PRIVATE_SENTINEL"), "timeout"),
            (ssl.SSLCertVerificationError("PRIVATE_SENTINEL"), "certificate"),
        ]
        for error, expected in cases:
            with self.subTest(error=type(error)), tempfile.TemporaryDirectory() as directory, patch(
                "vaptkit.assessment.observe", side_effect=error
            ):
                output, code = assess(self.config, self.approval, Path(directory) / "out")
                self.assertEqual(code, 1)
                text = output.read_text()
                self.assertIn(expected, text)
                self.assertNotIn("PRIVATE_SENTINEL", text)

    def test_token_approval_bound_and_never_persisted(self):
        self.config["access"] = {"type": "bearer", "token_env": "VAPT_TEST_TOKEN", "header": "Proxy-Authorization"}
        with self.assertRaises(ToolError):
            validate_approval(self.config, self.approval)
        self.approval = approved(self.config)
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            "os.environ", {"VAPT_TEST_TOKEN": "private-test-token"}
        ), patch("vaptkit.assessment.observe", return_value=observation(protected=True)) as request:
            output, code = assess(self.config, self.approval, Path(directory) / "out")
            result = json.loads(output.read_text())
            self.assertEqual(code, 0)
            self.assertEqual(result["profile"], "bearer-head-only")
            self.assertNotIn("private-test-token", output.read_text())
            self.assertEqual(request.call_args.kwargs["headers"], {"Proxy-Authorization": "Bearer private-test-token"})
            self.assertEqual(result["coverage"]["unauthorized_access"], "not_tested")
            validate_result(result)

    def test_invalid_tokens_stop_before_output_and_network(self):
        self.config["access"] = {"type": "bearer", "token_env": "VAPT_TEST_TOKEN", "header": "Proxy-Authorization"}
        self.approval = approved(self.config)
        for token in ("", " abc", "abc\n", "abc\r\nInjected: yes", "a" * 16385):
            with self.subTest(length=len(token)), tempfile.TemporaryDirectory() as directory, patch.dict(
                "os.environ", {"VAPT_TEST_TOKEN": token}
            ), patch("vaptkit.assessment.observe") as request:
                output = Path(directory) / "out"
                with self.assertRaises(ToolError):
                    assess(self.config, self.approval, output)
                request.assert_not_called()
                self.assertFalse(output.exists())

    def test_invalid_json_does_not_echo_or_crash(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input.json"
            for text in ('{"paths":[],"paths":["/"]}', '{"x":NaN}', '{"x":Infinity}', '[' * 2000):
                path.write_text(text)
                with self.assertRaises(ToolError):
                    load_json(path)

    def test_failures_and_redirects_do_not_produce_header_findings(self):
        for status in (301, 404, 503):
            self.assertEqual(findings_for(observation(status=status)), [])

    def test_api_does_not_need_html_policy(self):
        item = observation()
        item["checks"]["html_response"] = False
        self.assertEqual(len(findings_for(item)), 2)
        self.assertEqual(findings_for(observation(protected=True)), [])


class NetworkTests(unittest.TestCase):
    def test_approval_expiring_during_dns_does_not_connect(self):
        with patch("socket.getaddrinfo", return_value=[(0, 0, 0, "", ("8.8.8.8", 443))]), patch(
            "socket.create_connection"
        ) as connect:
            with self.assertRaises(ToolError):
                observe("staging.example.com", "/", expires_at=datetime.now(timezone.utc) - timedelta(seconds=1))
            connect.assert_not_called()

    def test_timeout_bounded_by_expiry(self):
        now = datetime.now(timezone.utc)
        self.assertLessEqual(remaining_timeout(now + timedelta(seconds=2)), 2)
        self.assertEqual(remaining_timeout(now + timedelta(seconds=60)), 10)
        self.assertEqual(remaining_timeout(now + timedelta(seconds=120), 60), 60)
        self.assertLessEqual(remaining_timeout(now + timedelta(seconds=2), 60), 2)

    def test_csp_url_does_not_count_as_frame_directive(self):
        response = MagicMock(status=200)
        headers = {"Content-Security-Policy": "script-src https://example.invalid/frame-ancestors",
                   "X-Content-Type-Options": " nosniff "}
        response.getheader.side_effect = lambda key, default=None: headers.get(key, default)
        with patch("socket.getaddrinfo", return_value=[(0, 0, 0, "", ("8.8.8.8", 443))]), patch(
            "socket.create_connection"
        ), patch("ssl.create_default_context"), patch("http.client.HTTPSConnection") as connection:
            connection.return_value.getresponse.return_value = response
            item = observe("staging.example.com", "/")
            self.assertFalse(item["checks"]["frame_policy_present"])
            self.assertTrue(item["checks"]["nosniff"])
            headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'"
            self.assertTrue(observe("staging.example.com", "/")["checks"]["frame_policy_present"])

    def test_private_address_denied_before_connect(self):
        for ip in ("127.0.0.1", "10.0.0.1", "::1", "169.254.169.254"):
            with patch("socket.getaddrinfo", return_value=[(0, 0, 0, "", (ip, 443))]), patch(
                "socket.create_connection"
            ) as connect:
                with self.assertRaises(ToolError):
                    observe("staging.example.com", "/")
                connect.assert_not_called()

    def test_head_only_pinned_ip_no_redirect_or_body(self):
        headers = {
            "Content-Type": "text/html", "Location": "https://private.example/",
            "Set-Cookie": "PRIVATE_SENTINEL", "Server": "PRIVATE_SENTINEL",
        }
        response = MagicMock(status=302)
        response.getheader.side_effect = lambda key, default=None: headers.get(key, default)
        with patch("socket.getaddrinfo", return_value=[(0, 0, 0, "", ("8.8.8.8", 443))]), patch(
            "socket.create_connection"
        ) as connect, patch("ssl.create_default_context") as tls, patch(
            "http.client.HTTPSConnection"
        ) as connection:
            connection.return_value.getresponse.return_value = response
            item = observe("staging.example.com", "/")
            connect.assert_called_once_with(("8.8.8.8", 443), timeout=10)
            tls.return_value.wrap_socket.assert_called_once_with(
                connect.return_value, server_hostname="staging.example.com"
            )
            self.assertEqual(connection.return_value.request.call_count, 1)
            self.assertEqual(connection.return_value.request.call_args.args[:2], ("HEAD", "/"))
            response.read.assert_not_called()
            self.assertNotIn("PRIVATE_SENTINEL", json.dumps(item))
            connection.return_value.close.assert_called_once()
