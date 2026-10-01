import json
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from test_assessment import approved, observation
from test_roles import Application, ENV, approval_for, configuration
from vaptkit.assessment import assess
from vaptkit.process import ToolError
from vaptkit.report import render, validate_result
from vaptkit.roles import run, validate
from vaptkit.service_login import ServiceAccountAccess

ACCOUNT = "fixture-pilot@fixture-project.iam.gserviceaccount.com"
TOKEN = "SYNTHETIC.JWT.SENTINEL"


def keyless_config():
    config = configuration()
    config["access"] = {"type": "iap-service-account", "service_account": ACCOUNT}
    return config


class ServiceLoginTests(unittest.TestCase):
    def setUp(self):
        self.config = keyless_config()
        self.approval = approved(self.config)
        self.gcloud = patch("vaptkit.service_login.subprocess.run", return_value=SimpleNamespace(
            returncode=0, stdout="SYNTHETIC_ACCESS_SENTINEL\n"
        )).start()
        self.request = patch("vaptkit.service_login.request", return_value=(
            200, {}, json.dumps({"signedJwt": TOKEN}).encode()
        )).start()
        self.addCleanup(patch.stopall)

    def test_exact_audience_expiry_cache_and_secret_free_subprocess(self):
        with patch.dict("os.environ", ENV):
            session = ServiceAccountAccess(self.config, self.approval)
            self.assertEqual(session.headers(), {"Proxy-Authorization": "Bearer " + TOKEN})
            self.assertEqual(session.headers(), {"Proxy-Authorization": "Bearer " + TOKEN})
        self.gcloud.assert_called_once()
        args = self.request.call_args
        self.assertEqual(args.args, ("iamcredentials.googleapis.com", "POST",
                                   f"/v1/projects/-/serviceAccounts/{ACCOUNT}:signJwt"))
        payload = json.loads(json.loads(args.kwargs["body"])["payload"])
        self.assertEqual(payload["iss"], ACCOUNT)
        self.assertEqual(payload["sub"], ACCOUNT)
        self.assertEqual(payload["aud"], self.config["target"]["url"] + "/*")
        self.assertLessEqual(payload["exp"] - payload["iat"], 300)
        for name in ENV:
            self.assertNotIn(name, self.gcloud.call_args.kwargs["env"])
        self.assertNotIn(TOKEN, repr(self.gcloud.call_args))
        session.clear()
        self.assertEqual(session._token, "")

    def test_refreshes_before_expiry(self):
        session = ServiceAccountAccess(self.config, self.approval)
        session.headers()
        session._expires_at = datetime.now(timezone.utc) + timedelta(seconds=15)
        session.headers()
        self.assertEqual(self.request.call_count, 2)

    def test_cached_token_never_bypasses_expired_approval(self):
        session = ServiceAccountAccess(self.config, self.approval)
        session.headers()
        self.approval["expires_at"] = "2000-01-01T00:00:00Z"
        with self.assertRaises(ToolError):
            session.headers()
        self.request.assert_called_once()

    def test_token_expiry_is_bounded_by_approval(self):
        self.approval["expires_at"] = (datetime.now(timezone.utc) + timedelta(seconds=90)).isoformat()
        session = ServiceAccountAccess(self.config, self.approval)
        session.headers()
        payload = json.loads(json.loads(self.request.call_args.kwargs["body"])["payload"])
        self.assertLessEqual(payload["exp"] - payload["iat"], 90)

    def test_signing_failures_are_sanitized_and_not_retried(self):
        for status, body in (
            (403, b"SYNTHETIC_ACCESS_SENTINEL"), (302, b"SYNTHETIC_ACCESS_SENTINEL"),
            (200, b"invalid SYNTHETIC_ACCESS_SENTINEL"),
            (200, b'{"signedJwt":"invalid"}'), (200, b"x" * 16385),
            (200, b'{"signedJwt":"a.b.c","signedJwt":"d.e.f"}'),
        ):
            with self.subTest(status=status, body_length=len(body)):
                self.request.reset_mock()
                self.request.return_value = status, {}, body
                with self.assertRaises(ToolError) as error:
                    ServiceAccountAccess(self.config, self.approval).headers()
                self.assertNotIn("SYNTHETIC", str(error.exception))
                self.request.assert_called_once()

    def test_gcloud_failures_never_send_signing_request(self):
        for failure in (FileNotFoundError(), subprocess.TimeoutExpired("gcloud", 1, output=TOKEN)):
            self.gcloud.side_effect = failure
            with self.assertRaises(ToolError) as error:
                ServiceAccountAccess(self.config, self.approval).headers()
            self.assertNotIn(TOKEN, str(error.exception))
        self.gcloud.side_effect = None
        self.gcloud.return_value = SimpleNamespace(returncode=1, stdout=TOKEN)
        with self.assertRaises(ToolError):
            ServiceAccountAccess(self.config, self.approval).headers()
        self.request.assert_not_called()

    def test_invalid_scope_stops_before_gcloud(self):
        self.approval["config_sha256"] = "0" * 64
        with self.assertRaises(ToolError):
            ServiceAccountAccess(self.config, self.approval)
        self.gcloud.assert_not_called()
        self.request.assert_not_called()

    def test_role_matrix_keeps_application_sessions_isolated(self):
        app = Application()
        with tempfile.TemporaryDirectory() as directory, patch.dict("os.environ", ENV), patch(
            "vaptkit.roles.request", side_effect=app
        ), patch("vaptkit.roles.time.sleep"), patch("vaptkit.roles.browser_login") as browser:
            output, code = run(self.config, approval_for(self.config), Path(directory) / "out")
            result = json.loads(output.read_text())
            validate_result(result)
            self.assertEqual(code, 0)
            self.assertNotIn(TOKEN, output.read_text() + render(result))
            self.assertNotIn("SYNTHETIC_ACCESS_SENTINEL", output.read_text() + render(result))
            browser.assert_not_called()
        self.request.assert_called_once()
        for method, path, kwargs in app.calls:
            self.assertEqual(kwargs["headers"]["Proxy-Authorization"], "Bearer " + TOKEN)
            if path.endswith("signin") or kwargs is app.calls[0][2]:
                self.assertNotIn("Cookie", kwargs["headers"])

    def test_signing_denial_prevents_application_requests_and_marks_incomplete(self):
        self.request.return_value = (403, {}, b"SYNTHETIC_ACCESS_SENTINEL")
        with tempfile.TemporaryDirectory() as directory, patch.dict("os.environ", ENV), patch(
            "vaptkit.roles.request"
        ) as application:
            output, code = run(self.config, approval_for(self.config), Path(directory) / "out")
            result = json.loads(output.read_text())
            validate_result(result)
            self.assertEqual(code, 1)
            self.assertEqual(result["requests"], [])
            self.assertIn("HTTP 403", result["errors"][0]["message"])
            self.assertNotIn("SYNTHETIC", output.read_text())
            application.assert_not_called()

    def test_header_profile_uses_keyless_credentials_and_exports_safely(self):
        with tempfile.TemporaryDirectory() as directory, patch(
            "vaptkit.assessment.observe", return_value=observation(protected=True)
        ) as observe:
            output, code = assess(self.config, self.approval, Path(directory) / "out")
            result = json.loads(output.read_text())
            validate_result(result)
            self.assertEqual(code, 0)
            self.assertEqual(result["profile"], "iap-service-account-head-only")
            self.assertIn("keyless Google IAP access", render(result))
            self.assertNotIn(TOKEN, output.read_text() + render(result))
            self.assertEqual(observe.call_args.kwargs["headers"]["Proxy-Authorization"], "Bearer " + TOKEN)

    def test_role_approval_is_not_reinterpreted_as_head_scope(self):
        approval = approval_for(self.config)
        session = ServiceAccountAccess(self.config, approval, validate_scope=validate)
        session.headers()
        self.assertEqual(approval["method"], "GET")
        self.assertTrue(approval["role_login"])
