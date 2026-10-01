import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from test_assessment import ROOT, approved
from vaptkit.config import load_config
from vaptkit.process import ToolError
from vaptkit.report import render, validate_result
from vaptkit.roles import BODY_LIMIT, LOGIN, LOGOUT, collect_cookies, matches_shape, run, template, validate


def configuration():
    config = load_config(ROOT / "projects/dtap.vapt.yml")
    config["role_testing"]["accounts"] = [config["role_testing"]["accounts"][0],
                                         config["role_testing"]["accounts"][3]]
    return config


def approval_for(config):
    approval = template(config)
    ordinary = approved(config)
    approval.update({key: ordinary[key] for key in ("approved_by", "starts_at", "expires_at")})
    approval["role_login"] = True
    return approval


ENV = {
    "DTAP_SP_EMAIL": "fixture-sp@example.invalid", "DTAP_LEAD_EMAIL": "fixture-lead@example.invalid",
    "DTAP_QA_PASSWORD": "SYNTHETIC_PASSWORD_SENTINEL",
}


def reply(status, body, cookies=None, content_type="application/json"):
    headers = {"content-type": [content_type]}
    if cookies:
        headers["set-cookie"] = cookies
    return status, headers, json.dumps(body).encode()


class Application:
    def __init__(self, vulnerable=False, catchall=False):
        self.vulnerable, self.catchall = vulnerable, catchall
        self.calls = []

    def __call__(self, host, method, path, **kwargs):
        self.calls.append((method, path, kwargs))
        if path == LOGIN:
            data = json.loads(kwargs["body"])
            lead = data["email"] == ENV["DTAP_LEAD_EMAIL"]
            return reply(200, {"user": {"email": data["email"], "user_type": "lead-evaluator" if lead else "service-provider"}},
                         [f"auth-token={'lead' if lead else 'provider'}; Path=/; Secure; HttpOnly",
                          "session-bind=SYNTHETIC_BIND_SENTINEL; Path=/; Secure; HttpOnly"])
        if path == LOGOUT:
            return reply(200, {"success": True})
        lead = "auth-token=lead;" in kwargs["headers"].get("Cookie", "")
        if not lead and self.catchall:
            return reply(200, {"message": "login required"})
        if lead or self.vulnerable:
            return reply(200, {"data": [{"fixture": "SYNTHETIC_BODY_SENTINEL"}], "stats": {}})
        return reply(403 if kwargs["headers"].get("Cookie") else 401, {"error": "denied"})


class RoleTests(unittest.TestCase):
    def execute(self, app, config=None):
        config = config or configuration()
        with tempfile.TemporaryDirectory() as directory, patch.dict("os.environ", ENV), patch(
            "vaptkit.roles.request", side_effect=app
        ), patch("vaptkit.roles.time.sleep"):
            destination, code = run(config, approval_for(config), Path(directory) / "out")
            text = destination.read_text()
            result = json.loads(text)
            validate_result(result)
            for sentinel in (*ENV.values(), "SYNTHETIC_BIND_SENTINEL", "SYNTHETIC_BODY_SENTINEL"):
                self.assertNotIn(sentinel, text)
                self.assertNotIn(sentinel, render(result))
            self.assertEqual(destination.stat().st_mode & 0o777, 0o600)
            return result, code

    def test_secure_matrix_and_isolated_sessions(self):
        app = Application()
        result, code = self.execute(app)
        self.assertEqual(code, 0)
        self.assertEqual(result["findings"], [])
        self.assertEqual(len(result["role_observations"]), 3)
        self.assertEqual([item["status"] for item in result["role_cleanup"]], ["acknowledged"] * 2)
        get_calls = [call for call in app.calls if call[0] == "GET"]
        self.assertNotIn("Cookie", get_calls[0][2]["headers"])
        self.assertIn("auth-token=provider;", get_calls[1][2]["headers"]["Cookie"])
        self.assertIn("auth-token=lead;", get_calls[2][2]["headers"]["Cookie"])
        self.assertTrue(all(path in (LOGIN, LOGOUT) for method, path, _ in app.calls if method == "POST"))
        self.assertEqual(result["coverage"]["unauthorized_access"], "tested")
        document = render(result)
        self.assertIn("Endpoint Role Matrix", document)
        self.assertNotIn("sent only HTTP HEAD", document)

    def test_repeated_bypass_requires_shape_and_positive_control(self):
        result, code = self.execute(Application(vulnerable=True))
        self.assertEqual(code, 0)
        self.assertEqual(len(result["findings"]), 2)
        self.assertEqual({item["verification"] for item in result["findings"]}, {"confirmed"})
        self.assertEqual([len(item["attempts"]) for item in result["role_observations"]], [2, 2, 1])

    def test_iap_is_shared_without_sharing_application_sessions(self):
        config = configuration()
        config["access"] = {"type": "iap-browser", "remember_login": True}
        gateway = "GCP_IAP_AUTH_TOKEN_test=SYNTHETIC_GATEWAY_SENTINEL"
        app = Application()
        with patch("vaptkit.roles.browser_login", return_value={"Cookie": gateway}) as login:
            result, code = self.execute(app, config)
        self.assertEqual(code, 0)
        self.assertIs(login.call_args.kwargs["validate_scope"], validate)
        self.assertEqual(login.call_args.args[1]["method"], "GET")
        self.assertTrue(login.call_args.args[1]["role_login"])
        for method, path, kwargs in app.calls:
            cookies = kwargs["headers"]["Cookie"]
            self.assertTrue(cookies.startswith(gateway))
            if path == LOGIN:
                self.assertEqual(cookies, gateway)
            self.assertFalse("auth-token=lead" in cookies and "auth-token=provider" in cookies)
        self.assertEqual(app.calls[0][2]["headers"]["Cookie"], gateway)
        self.assertEqual(result["findings"], [])
        self.assertIn("Public access outside IAP was not tested", result["coverage"]["note"])
        self.assertNotIn("SYNTHETIC_GATEWAY_SENTINEL", json.dumps(result) + render(result))

    def test_iap_failure_sends_no_matrix_requests(self):
        config = configuration()
        config["access"] = {"type": "iap-browser"}
        app = Application()
        with patch("vaptkit.roles.browser_login", side_effect=ToolError("Manual IAP login timed out.")):
            result, code = self.execute(app, config)
        self.assertEqual(code, 1)
        self.assertEqual(app.calls, [])
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["coverage"]["unauthorized_access"], "not_tested")

    def test_iap_redirect_or_denial_is_not_a_passing_matrix(self):
        config = configuration()
        config["access"] = {"type": "iap-browser"}
        for status in (302, 401, 403):
            calls = []
            def app(host, method, path, **kwargs):
                calls.append((method, path))
                return reply(status, {"error": "gateway"})
            with self.subTest(status=status), patch(
                "vaptkit.roles.browser_login", return_value={"Cookie": "GCP_IAP_AUTH_TOKEN_test=fixture"}
            ):
                result, code = self.execute(app, config)
            self.assertEqual(code, 1)
            self.assertEqual(result["findings"], [])
            self.assertEqual(result["coverage"]["unauthorized_access"], "not_tested")
            self.assertEqual(len(calls), 1 if status == 302 else 2)

    def test_bearer_access_remains_unsupported(self):
        config = configuration()
        config["access"] = {"type": "bearer", "token_env": "TOKEN", "header": "Authorization"}
        with self.assertRaisesRegex(ToolError, "not bearer"):
            validate(config, approval_for(config))

    def test_scope_expiry_stops_requests_including_signout(self):
        app = Application()
        calls = 0
        def validate_until_login(config, approval):
            nonlocal calls
            calls += 1
            if calls == 4:
                raise ToolError("Approval expired.")
            validate(config, approval)
        with patch("vaptkit.roles.validate", side_effect=validate_until_login):
            result, code = self.execute(app)
        self.assertEqual(code, 1)
        self.assertEqual([method for method, _, _ in app.calls], ["GET", "POST"])
        self.assertEqual(app.calls[-1][1], LOGIN)
        self.assertEqual(result["role_cleanup"][0]["status"], "unconfirmed")
        self.assertEqual(calls, 4)

    def test_generic_success_is_suspected_not_confirmed(self):
        result, code = self.execute(Application(catchall=True))
        self.assertEqual(code, 1)
        self.assertEqual({item["verification"] for item in result["findings"]}, {"suspected"})

    def test_json_shape_rejects_errors_truncation_wrong_types_and_duplicates(self):
        headers = {"content-type": ["application/json"]}
        shape = {"data": "array", "stats": "object"}
        for body in (b'{"data":[],"stats":{},"error":"denied"}', b'{"data":null,"stats":{}}',
                     b'{"data":[],"stats":{},"success":false}', b'{"data":[],"data":[],"stats":{}}',
                     b'{"data":[],"stats":{}' + b" " * BODY_LIMIT):
            self.assertFalse(matches_shape(headers, body, shape))
        self.assertFalse(matches_shape({"content-type": ["text/html"]}, b'{"data":[],"stats":{}}', shape))
        self.assertTrue(matches_shape(headers, b'{"data":[],"stats":{}}', shape))

    def test_scope_defaults_invalid_and_no_traffic_without_secrets(self):
        config = configuration()
        with self.assertRaises(ToolError):
            validate(config, template(config))
        approval = approval_for(config)
        cases = [
            {"role_login": False}, {"method": "POST"}, {"role_accounts": ["service-provider"]},
            {"role_accounts": ["lead-evaluator", "lead-evaluator"]}, {"role_accounts": ["unknown"]},
            {"paths": ["/api/auth/signout"]}, {"exposure_checks": True},
        ]
        for change in cases:
            with self.subTest(change=change), self.assertRaises(ToolError):
                validate(config, dict(approval, **change))
        with tempfile.TemporaryDirectory() as directory, patch.dict("os.environ", {}, clear=True), patch(
            "vaptkit.roles.request"
        ) as request:
            with self.assertRaises(ToolError):
                run(config, approval, Path(directory) / "out")
            request.assert_not_called()

    def test_wrong_login_identity_stops_and_attempts_signout(self):
        base = Application()
        def app(host, method, path, **kwargs):
            status, headers, body = base(host, method, path, **kwargs)
            if path == LOGIN:
                body = b'{"user":{"email":null,"user_type":"administrator"}}'
            return status, headers, body
        result, code = self.execute(app)
        self.assertEqual(code, 1)
        self.assertEqual(base.calls[-1][1], LOGOUT)
        self.assertEqual(sum(path == LOGIN for _, path, _ in base.calls), 1)
        self.assertNotIn("confirmed", {item["verification"] for item in result["findings"]})

    def test_login_denial_is_not_retried(self):
        calls = []
        def app(host, method, path, **kwargs):
            calls.append((method, path))
            return reply(401, {"error": "denied"})
        result, code = self.execute(app)
        self.assertEqual(code, 1)
        self.assertEqual(sum(path == LOGIN for _, path in calls), 1)
        self.assertEqual(calls[-1][1], LOGIN)

    def test_rate_limit_redirect_server_and_transport_errors_stop_cleanup_traffic(self):
        for status in (302, 429, 503, None):
            with self.subTest(status=status):
                base = Application()
                calls = []
                def app(host, method, path, **kwargs):
                    calls.append((method, path))
                    if method == "GET" and kwargs["headers"].get("Cookie"):
                        if status is None:
                            raise TimeoutError("SYNTHETIC_BODY_SENTINEL")
                        return reply(status, {})
                    return base(host, method, path, **kwargs)
                result, code = self.execute(app)
                self.assertEqual(code, 1)
                self.assertEqual(calls[-1][0], "GET")
                self.assertEqual(result["role_cleanup"][0]["status"], "unconfirmed")

    def test_cookie_constraints(self):
        for cookie in ("auth-token=x; Path=/; HttpOnly",
                       "auth-token=x; Path=/; Secure; HttpOnly; Domain=outside.invalid",
                       "auth-token=x; Path=/nested; Secure; HttpOnly"):
            with self.subTest(cookie=cookie), self.assertRaises(ToolError):
                collect_cookies({"set-cookie": [cookie]}, "test.dtap.dict.gov.ph")

    def test_failed_logout_marks_incomplete(self):
        base = Application()
        def app(host, method, path, **kwargs):
            if path == LOGOUT:
                return reply(200, {"success": False})
            return base(host, method, path, **kwargs)
        result, code = self.execute(app)
        self.assertEqual(code, 1)
        self.assertEqual(result["role_cleanup"][0]["status"], "unconfirmed")

    def test_report_rejects_missing_role_cell_or_cleanup(self):
        result, _ = self.execute(Application())
        for key in ("role_observations", "role_cleanup"):
            bad = copy.deepcopy(result)
            bad[key].pop()
            with self.assertRaises(ToolError):
                validate_result(bad)
