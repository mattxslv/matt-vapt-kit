import unittest
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from test_assessment import approved
from test_roles import approval_for, configuration, validate
from vaptkit.browser_login import iap_cookie_header, login, login_request_allowed, profile_directory
from vaptkit.process import ToolError

ORIGIN = "https://staging.example.invalid"


class BrowserError(Exception):
    pass


class BrowserLoginTests(unittest.TestCase):
    def test_head_and_role_approvals_are_validated_before_reusing_iap(self):
        for role_check in (False, True):
            config = configuration()
            config["access"] = {"type": "iap-browser"}
            approval = approval_for(config) if role_check else approved(config)
            browser_api = MagicMock()
            browser = browser_api.return_value.__enter__.return_value.chromium.launch.return_value
            context = browser.new_context.return_value
            context.cookies.return_value = [
                {"name": "auth-token", "value": "UNWANTED_APP_SESSION", "secure": True},
                {"name": "GCP_IAP_AUTH_TOKEN_test", "value": "fixture", "secure": True},
            ]
            module = SimpleNamespace(Error=BrowserError, sync_playwright=browser_api)
            options = {"validate_scope": validate} if role_check else {}
            with self.subTest(role_check=role_check), patch.dict(
                "sys.modules", {"playwright.sync_api": module}
            ), patch("vaptkit.assessment.public_addresses"), patch("builtins.print"):
                self.assertEqual(login(config, approval, **options),
                                 {"Cookie": "GCP_IAP_AUTH_TOKEN_test=fixture"})
            context.close.assert_called_once()
            browser.close.assert_called_once()
            context.new_page.assert_not_called()

    def test_expired_scope_after_browser_start_cannot_reuse_saved_cookie(self):
        config = configuration()
        config["access"] = {"type": "iap-browser"}
        browser_api = MagicMock()
        browser = browser_api.return_value.__enter__.return_value.chromium.launch.return_value
        context = browser.new_context.return_value
        validator = MagicMock(side_effect=[None, ToolError("Approval expired.")])
        module = SimpleNamespace(Error=BrowserError, sync_playwright=browser_api)
        with patch.dict("sys.modules", {"playwright.sync_api": module}), patch(
            "vaptkit.assessment.public_addresses"
        ), patch("builtins.print"), self.assertRaisesRegex(ToolError, "Approval expired"):
            login(config, approval_for(config), validate_scope=validator)
        context.cookies.assert_not_called()
        context.close.assert_called_once()
        browser.close.assert_called_once()

    def test_saved_profiles_are_private_and_origin_separated(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict("os.environ", {"XDG_STATE_HOME": directory}):
            first = profile_directory(ORIGIN)
            second = profile_directory("https://another.example.invalid")
            self.assertNotEqual(first, second)
            self.assertEqual(first.stat().st_mode & 0o777, 0o700)
            self.assertEqual(first.parent.stat().st_mode & 0o777, 0o700)
            self.assertTrue(first.is_relative_to(Path(directory)))
            self.assertEqual(first, profile_directory(ORIGIN))
    def test_only_iap_cookies_are_selected(self):
        cookies = [
            {"name": "app_session", "value": "PRIVATE_APP", "secure": True},
            {"name": "GCP_IAP_AUTH_TOKEN_test", "value": "test.iap.token", "secure": True},
            {"name": "google_session", "value": "PRIVATE_GOOGLE", "secure": True},
        ]
        self.assertEqual(iap_cookie_header(cookies), "GCP_IAP_AUTH_TOKEN_test=test.iap.token")
        self.assertEqual(iap_cookie_header(cookies[:1]), "")

    def test_cookie_header_injection_rejected(self):
        for value, secure in (("a\r\nInjected: x", True), ("valid", False), ("x" * 17000, True)):
            with self.assertRaises(ToolError):
                iap_cookie_header([{"name": "GCP_IAP_AUTH_TOKEN_test", "value": value, "secure": secure}])

    def test_login_route_boundaries(self):
        cases = [
            (ORIGIN + "/", "GET", True),
            (ORIGIN + "/api/admin/delete", "POST", False),
            (ORIGIN + "/_gcp_iap/authenticate", "POST", True),
            (ORIGIN + "/api/admin/export?x=y", "GET", False),
            (ORIGIN + "/api/admin/%65xport", "GET", False),
            (ORIGIN + "/api/../admin", "GET", False),
            ("https://accounts.google.com/v3/signin/", "POST", True),
            ("https://ssl.gstatic.com/account.js", "GET", True),
            ("https://evilgstatic.com/account.js", "GET", False),
            ("https://accounts.google.com.evil.invalid/", "POST", False),
            ("https://production.example.invalid/", "GET", False),
            ("http://accounts.google.com/", "GET", False),
            ("https://accounts.google.com:8443/", "GET", False),
        ]
        for url, method, allowed in cases:
            with self.subTest(url=url, method=method):
                self.assertEqual(login_request_allowed(url, method, ORIGIN, ["/api/admin/export"]), allowed)
