"""Proves role_testing is genuinely config-driven, not DTAP-shaped: a second real app (PEMEDES) uses a
different login path, a bearer token instead of cookies, and a different role field name (`role`, not
`user_type`). Shapes here are taken directly from PEMEDES's app/api/auth/cloudsql/signin/route.ts and
lib/cloudsql/auth.ts (POST {email,password} -> {user: {..., role}, session: {access_token}})."""
import json
import unittest
from pathlib import Path
from unittest.mock import patch

from vaptkit.process import ToolError
from vaptkit.roles import run, template, validate

LOGIN_PATH = "/api/auth/cloudsql/signin"
LOGOUT_PATH = "/api/auth/signout"
ROUTE_PATH = "/api/operator-applications"
ENV = {"PEMEDES_ADMIN_EMAIL": "fixture-admin@example.invalid", "PEMEDES_AGENT_EMAIL": "fixture-agent@example.invalid",
      "PEMEDES_QA_PASSWORD": "SYNTHETIC_PASSWORD_SENTINEL"}


def configuration() -> dict:
    return {
        "schema_version": 1, "project": "pemedes-shaped-fixture",
        "target": {"environment": "staging", "url": "https://staging.example.invalid",
                   "allowed_hosts": ["staging.example.invalid"], "verification": "reachable-not-authorized"},
        "scope": {"api_prefixes": ["/api/"], "excluded_prefixes": [], "roles": ["admin", "agent"]},
        "credentials": {},
        "role_testing": {
            "adapter": "session-login-v1",
            "login": {
                "login_path": LOGIN_PATH, "logout_path": LOGOUT_PATH, "identity_path": ["user"],
                "email_field": "email", "role_field": "role",
                "session": {"type": "bearer", "token_path": ["session", "access_token"], "header": "Authorization"},
            },
            "accounts": [
                {"id": "admin", "role": "admin", "email_env": "PEMEDES_ADMIN_EMAIL", "password_env": "PEMEDES_QA_PASSWORD"},
                {"id": "agent", "role": "agent", "email_env": "PEMEDES_AGENT_EMAIL", "password_env": "PEMEDES_QA_PASSWORD"},
            ],
            "routes": [{"path": ROUTE_PATH, "allowed_roles": ["admin"], "response_shape": {"data": "array"}}],
        },
    }


def reply(status, body, headers=None):
    return status, {"content-type": ["application/json"], **(headers or {})}, json.dumps(body).encode()


class BearerTokenApplication:
    """A login/route pair shaped like PEMEDES: Authorization: Bearer <token>, no cookies anywhere."""

    def __init__(self):
        self.calls = []

    def __call__(self, host, method, path, **kwargs):
        self.calls.append((method, path, kwargs))
        self.assertNoCookieHeader(kwargs["headers"])
        if path == LOGIN_PATH:
            data = json.loads(kwargs["body"])
            admin = data["email"] == ENV["PEMEDES_ADMIN_EMAIL"]
            return reply(200, {"user": {"email": data["email"], "role": "admin" if admin else "agent"},
                               "session": {"access_token": "SYNTHETIC_TOKEN_" + ("admin" if admin else "agent")}})
        if path == LOGOUT_PATH:
            return reply(200, {"success": True})
        auth = kwargs["headers"].get("Authorization", "")
        if auth == "Bearer SYNTHETIC_TOKEN_admin":
            return reply(200, {"data": [{"fixture": "SYNTHETIC_BODY_SENTINEL"}]})
        return reply(403 if auth else 401, {"error": "denied"})

    @staticmethod
    def assertNoCookieHeader(headers):
        assert "Cookie" not in headers, "a bearer-token login should never send a Cookie header"


class BearerLoginTests(unittest.TestCase):
    def execute(self, app):
        config = configuration()
        approval = template(config)
        from datetime import datetime, timedelta, timezone
        now = datetime.now(timezone.utc)
        approval.update(approved_by="tester", starts_at=now.isoformat(),
                        expires_at=(now + timedelta(hours=1)).isoformat(), role_login=True)
        with patch.dict("os.environ", ENV), patch("vaptkit.roles.request", side_effect=app), \
                patch("vaptkit.roles.time.sleep"):
            import tempfile
            with tempfile.TemporaryDirectory() as directory:
                destination, code = run(config, approval, Path(directory) / "out")
                result = json.loads(destination.read_text())
                for sentinel in (*ENV.values(), "SYNTHETIC_BODY_SENTINEL"):
                    self.assertNotIn(sentinel, destination.read_text())
                return result, code

    def test_bearer_login_identifies_roles_and_confirms_the_positive_control(self):
        app = BearerTokenApplication()
        result, code = self.execute(app)
        self.assertEqual(code, 0)
        admin_record = next(item for item in result["role_observations"] if item["account"] == "admin")
        self.assertEqual(role_outcome_of(admin_record), "allowed")
        agent_record = next(item for item in result["role_observations"] if item["account"] == "agent")
        self.assertTrue(all(attempt["status"] in (401, 403) for attempt in agent_record["attempts"]))
        self.assertEqual({item["status"] for item in result["role_cleanup"]}, {"acknowledged"})

    def test_rejects_the_dtap_adapter_name(self):
        config = configuration()
        config["role_testing"]["adapter"] = "dtap-cookie-v1"
        approval = template(config)
        with self.assertRaises(ToolError):
            validate(config, approval)


def role_outcome_of(record: dict) -> str:
    from vaptkit.roles import role_outcome
    return role_outcome(record, {record["path"]} if record["expected_allowed"]
                        and all(200 <= a["status"] < 300 and a["shape_matched"] for a in record["attempts"]) else set())
