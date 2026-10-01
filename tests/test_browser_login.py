import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch

from vaptkit.browser_login import iap_cookie_header, login_request_allowed, profile_directory
from vaptkit.process import ToolError

ORIGIN = "https://staging.example.invalid"


class BrowserLoginTests(unittest.TestCase):
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
