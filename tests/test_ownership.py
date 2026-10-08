import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from test_assessment import ROOT, approved
from vaptkit.config import load_config
from vaptkit.process import ToolError
from vaptkit.ownership import run, template, validate

ENV = {"DTAP_EVALUATOR_EMAIL": "fixture-eval@example.invalid", "DTAP_EVALUATOR2_EMAIL": "fixture-eval2@example.invalid",
      "DTAP_QA_PASSWORD": "SYNTHETIC_PASSWORD_SENTINEL"}
PROFILE_PATH = "/api/evaluator/profile"


def configuration():
    config = load_config(ROOT / "projects/dtap.vapt.yml")
    config.pop("access", None)
    config["role_testing"]["accounts"] = [item for item in config["role_testing"]["accounts"]
                                          if item["id"] in ("evaluator", "evaluator-2")]
    return config


LOGIN = configuration()["role_testing"]["login"]["login_path"]
LOGOUT = configuration()["role_testing"]["login"]["logout_path"]


def approval_for(config):
    approval = template(config)
    ordinary = approved(config)
    approval.update({key: ordinary[key] for key in ("approved_by", "starts_at", "expires_at")})
    approval["ownership_login"] = True
    approval["paths"] = [PROFILE_PATH]
    return approval


def reply(status, body, cookies=None):
    headers = {"content-type": ["application/json"]}
    if cookies:
        headers["set-cookie"] = cookies
    return status, headers, json.dumps(body).encode()


class VulnerableApp:
    """Models the real bug: PUT trusts the body's userId; GET always returns the caller's own record."""
    def __init__(self):
        self.records = {"eval-1-id": "Engineering", "eval-2-id": "Operations"}
        self.calls = []

    def session_user(self, cookie_header):
        return "eval-2-id" if "auth-token=eval2;" in cookie_header else "eval-1-id"

    def __call__(self, host, method, path, **kwargs):
        self.calls.append((method, path))
        if path == LOGIN:
            data = json.loads(kwargs["body"])
            second = data["email"] == ENV["DTAP_EVALUATOR2_EMAIL"]
            user_id = "eval-2-id" if second else "eval-1-id"
            return reply(200, {"user": {"id": user_id, "email": data["email"], "user_type": "evaluator"}},
                         [f"auth-token={'eval2' if second else 'eval1'}; Path=/; Secure; HttpOnly",
                          "session-bind=SYNTHETIC_BIND_SENTINEL; Path=/; Secure; HttpOnly"])
        if path == LOGOUT:
            return reply(200, {"success": True})
        caller = self.session_user(kwargs["headers"].get("Cookie", ""))
        if method == "GET" and path == PROFILE_PATH:
            return reply(200, {"profile": {"department": self.records[caller]}})
        if method == "PUT" and path == PROFILE_PATH:
            body = json.loads(kwargs["body"])
            self.records[body["userId"]] = body["department"]  # the bug: trusts body userId, not the session
            return reply(200, {"success": True})
        return reply(404, {"error": "not found"})


class FixedApp(VulnerableApp):
    """Models the fix: PUT always writes to the caller's own record, ignoring any userId in the body."""
    def __call__(self, host, method, path, **kwargs):
        if method == "PUT" and path == PROFILE_PATH:
            self.calls.append((method, path))
            caller = self.session_user(kwargs["headers"].get("Cookie", ""))
            body = json.loads(kwargs["body"])
            self.records[caller] = body["department"]
            return reply(200, {"success": True})
        return super().__call__(host, method, path, **kwargs)


class OwnershipTests(unittest.TestCase):
    def execute(self, app, config=None):
        config = config or configuration()
        with tempfile.TemporaryDirectory() as directory, patch.dict("os.environ", ENV), patch(
            "vaptkit.ownership.request", side_effect=app
        ), patch("vaptkit.ownership.time.sleep"):
            destination, code = run(config, approval_for(config), Path(directory) / "out")
            text = destination.read_text()
            result = json.loads(text)
            for sentinel in (*ENV.values(), "SYNTHETIC_BIND_SENTINEL"):
                self.assertNotIn(sentinel, text)
            self.assertEqual(destination.stat().st_mode & 0o777, 0o600)
            return result, code

    def test_confirms_the_real_bug_and_restores_the_value(self):
        app = VulnerableApp()
        result, code = self.execute(app)
        # code mirrors roles.py: 0 here means no coverage gaps, not "nothing was found" -- check findings for that.
        self.assertEqual(code, 0)
        self.assertEqual(len(result["findings"]), 1)
        finding = result["findings"][0]
        self.assertEqual(finding["verification"], "confirmed")
        self.assertEqual(finding["severity"], "high")
        self.assertIn("evaluator can change evaluator-2's record", finding["title"])
        self.assertEqual(app.records["eval-2-id"], "Operations")  # restored, not left as the probe value
        self.assertTrue(result["ownership_results"][0]["restored"])

    def test_fixed_endpoint_reports_no_findings(self):
        app = FixedApp()
        result, code = self.execute(app)
        self.assertEqual(result["findings"], [])
        self.assertEqual(app.records["eval-2-id"], "Operations")
        self.assertEqual(result["ownership_results"][0]["verdict"], "not_reproduced")

    def test_missing_ownership_login_is_rejected(self):
        config = configuration()
        approval = approval_for(config)
        approval["ownership_login"] = False
        with self.assertRaises(ToolError):
            validate(config, approval)

    def test_same_account_as_acting_and_target_is_rejected(self):
        config = configuration()
        config["ownership_checks"][0]["target_account"] = config["ownership_checks"][0]["acting_account"]
        with self.assertRaises(ToolError):
            validate(config, approval_for(config))

    def test_baseline_read_failure_aborts_before_any_write(self):
        def app(host, method, path, **kwargs):
            if path == LOGIN:
                data = json.loads(kwargs["body"])
                second = data["email"] == ENV["DTAP_EVALUATOR2_EMAIL"]
                return reply(200, {"user": {"id": "eval-2-id" if second else "eval-1-id", "email": data["email"],
                                            "user_type": "evaluator"}},
                             [f"auth-token={'eval2' if second else 'eval1'}; Path=/; Secure; HttpOnly",
                              "session-bind=SYNTHETIC_BIND_SENTINEL; Path=/; Secure; HttpOnly"])
            if path == LOGOUT:
                return reply(200, {"success": True})
            if method == "GET":
                return reply(500, {"error": "database down"})
            return reply(200, {"success": True})

        result, code = self.execute(app)
        self.assertEqual(result["findings"], [])
        self.assertEqual(code, 1)
        self.assertTrue(result["errors"])
