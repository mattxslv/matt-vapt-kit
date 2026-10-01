import unittest

from vaptkit.assessment import findings_for
from vaptkit.headers import csp_script_weaknesses, grade


def headers(**values):
    return {key.replace("_", "-"): ([v] if isinstance(v, str) else v) for key, v in values.items()}


STRONG = headers(
    content_type="text/html", strict_transport_security="max-age=31536000; includeSubDomains",
    content_security_policy="default-src 'self'; script-src 'self' 'nonce-abc' 'strict-dynamic' 'unsafe-inline'; object-src 'none'; frame-ancestors 'none'",
    x_content_type_options="nosniff", set_cookie=["auth-token=x; Path=/; Secure; HttpOnly; SameSite=Lax"],
    server="nginx",
)


class GradeTests(unittest.TestCase):
    def test_strong_headers_pass_everything(self):
        checks = grade(STRONG)
        self.assertTrue(all(checks.values()), checks)
        self.assertEqual(findings_for({"path": "/", "method": "HEAD", "status": 200, "checks": checks}), [])

    def test_csp_weaknesses(self):
        self.assertEqual(csp_script_weaknesses("default-src 'self'"), [])
        self.assertIn("'unsafe-inline'", csp_script_weaknesses("script-src 'self' 'unsafe-inline'; object-src 'none'"))
        self.assertEqual(csp_script_weaknesses("script-src 'nonce-a' 'unsafe-inline'; object-src 'none'"), [])
        self.assertIn("'unsafe-eval'", csp_script_weaknesses("default-src 'self' 'unsafe-eval'"))
        self.assertIn("https:", csp_script_weaknesses("default-src https:"))
        self.assertEqual(csp_script_weaknesses("default-src https: 'nonce-a' 'strict-dynamic'"), [])
        self.assertIn("no object-src", csp_script_weaknesses("script-src 'self'"))
        self.assertTrue(csp_script_weaknesses("frame-ancestors 'none'"))

    def test_weak_values_fail(self):
        checks = grade(headers(
            content_type="text/html", strict_transport_security="max-age=3600",
            content_security_policy="default-src * 'unsafe-inline'; frame-ancestors *",
            referrer_policy="unsafe-url", set_cookie=["sessionid=x; HttpOnly", "theme=dark; Secure"],
            x_powered_by="Next.js", server="Apache/2.4.1",
        ))
        for key in ("hsts_strong", "csp_script_strong", "frame_policy_strong", "referrer_policy_safe",
                    "cookies_secure", "no_version_disclosure"):
            self.assertFalse(checks[key], key)
        self.assertTrue(checks["session_cookies_httponly"])

    def test_httponly_only_required_for_session_like_cookies(self):
        self.assertTrue(grade(headers(set_cookie=["theme=dark; Secure"]))["session_cookies_httponly"])
        self.assertFalse(grade(headers(set_cookie=["session-bind=x; Secure"]))["session_cookies_httponly"])

    def test_missing_referrer_policy_is_not_a_finding(self):
        self.assertTrue(grade({})["referrer_policy_safe"])
        self.assertFalse(grade(headers(referrer_policy="no-referrer, unsafe-url"))["referrer_policy_safe"])

    def test_xfo_and_server_without_version(self):
        self.assertTrue(grade(headers(x_frame_options="SAMEORIGIN"))["frame_policy_strong"])
        self.assertFalse(grade(headers(x_frame_options="ALLOW-FROM https://x"))["frame_policy_strong"])
        self.assertTrue(grade(headers(server="Google Frontend"))["no_version_disclosure"])

    def test_graded_finding_not_duplicated_when_header_absent(self):
        checks = grade(headers(content_type="text/html"))
        titles = [f["title"] for f in findings_for({"path": "/", "method": "HEAD", "status": 200, "checks": checks})]
        self.assertIn("Content Security Policy not observed", titles)
        self.assertNotIn("Content Security Policy allows unsafe scripts", titles)
        self.assertNotIn("HSTS max-age is invalid or shorter than 180 days", titles)

    def test_legacy_records_without_graded_keys(self):
        legacy = {"html_response": True, "hsts_present": True, "csp_present": True, "nosniff": True,
                  "frame_policy_present": True}
        self.assertEqual(findings_for({"path": "/", "method": "HEAD", "status": 200, "checks": legacy}), [])


if __name__ == "__main__":
    unittest.main()
