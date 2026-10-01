import copy
import json
import socket
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

from vaptkit.assessment import (
    approval_template, assess, digest, findings_for, observe, validate_approval,
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
            {"interval_seconds": 0}, {"interval_seconds": True}, {"interval_seconds": float("nan")},
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

    def test_failures_and_redirects_do_not_produce_header_findings(self):
        for status in (301, 404, 503):
            self.assertEqual(findings_for(observation(status=status)), [])

    def test_api_does_not_need_html_policy(self):
        item = observation()
        item["checks"]["html_response"] = False
        self.assertEqual(len(findings_for(item)), 2)
        self.assertEqual(findings_for(observation(protected=True)), [])


class NetworkTests(unittest.TestCase):
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
