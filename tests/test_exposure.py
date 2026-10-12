import json
import unittest
from unittest.mock import Mock

from vaptkit.assessment import HTTPStop
from vaptkit.exposure import CHECKS, candidate, looks_like_baseline, run, signature_matches
from vaptkit.process import ToolError


def response(status=200, content_type="text/plain", body=b""):
    return status, {"content-type": [content_type], "content-length": [str(len(body))]}, body


class ExposureTests(unittest.TestCase):
    def test_soft_404_and_content_types(self):
        baseline = {"status": 200, "content_class": "html", "length": 500}
        headers = {"content-type": ["text/html"], "content-length": ["510"]}
        self.assertTrue(looks_like_baseline(200, headers, baseline))
        self.assertFalse(candidate("api_docs", 200, headers, baseline))
        for status in (302, 401, 403, 404, 429, 500):
            self.assertFalse(candidate("vcs", status, {"content-type": ["text/plain"]}, baseline))
        self.assertFalse(candidate("secret_file", 200, headers, {"status": 404}))
        self.assertTrue(candidate("vcs", 200, {"content-type": ["text/plain"]}, baseline))
        self.assertFalse(candidate("health", 200, {"content-type": ["text/plain"]}, baseline))

    def test_signatures_and_health_threshold(self):
        self.assertFalse(signature_matches("health", None, b'{"status":"ok"}'))
        self.assertFalse(signature_matches("health", None, b'{"version":"1","VERSION":"1"}'))
        self.assertTrue(signature_matches("health", None, b'{"version":"1","database":"fixture"}'))
        self.assertTrue(signature_matches("debug", None, b'{"config":{}}'))
        self.assertFalse(signature_matches("debug", None, b'{"error":"not found"}'))
        self.assertTrue(signature_matches("vcs", CHECKS[3][2], b"ref: refs/heads/main\n"))
        self.assertFalse(signature_matches("vcs", CHECKS[3][2], b"<html>Welcome</html>"))

    def scan(self, request, excluded=()):
        return run({"scope": {"excluded_prefixes": list(excluded)}}, {}, "fixture.invalid", {},
                   request, None, lambda: None)

    def test_spa_catchall_has_no_findings(self):
        fake = Mock(return_value=response(200, "text/html", b"<html>Welcome</html>"))
        records, findings = self.scan(fake)
        self.assertEqual(findings, [])
        self.assertFalse(any(item["exposed"] for item in records))

    def test_git_confirmed_no_body_or_cookie_persisted(self):
        def request(host, method, path, **kwargs):
            if path == "/.git/HEAD":
                self.assertEqual(kwargs["body_limit"], 2048 if method == "GET" else 0)
                if method == "GET":
                    self.assertEqual(kwargs["headers"], {"Range": "bytes=0-2047"})
                return response(body=b"ref: refs/heads/PRIVATE_SENTINEL\n")
            return response(404)
        records, findings = self.scan(request)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["verification"], "confirmed")
        self.assertEqual(findings[0]["path"], "/.git/HEAD")
        self.assertNotIn("PRIVATE_SENTINEL", json.dumps([records, findings]))

    def test_failed_get_and_missing_signature_never_confirm(self):
        for get_response in (response(404, body=b"ref: refs/heads/main"),
                             response(body=b"Welcome"), response(200, "text/html", b"ref: refs/heads/main")):
            with self.subTest(get_response=get_response):
                def request(host, method, path, **kwargs):
                    if path == "/.git/HEAD":
                        return response() if method == "HEAD" else get_response
                    return response(404)
                _, findings = self.scan(request)
                self.assertEqual(findings, [])

    def test_blocking_responses_stop_immediately_in_every_stage(self):
        for status in (302, 401, 403, 429, 503):
            for stage in ("baseline", "head", "get", "discovery"):
                with self.subTest(status=status, stage=stage):
                    calls = []
                    def request(host, method, path, **kwargs):
                        calls.append((method, path))
                        if ((stage == "baseline" and path.startswith("/mvk-baseline-"))
                                or (stage == "head" and path == "/.env")
                                or (stage == "get" and path == "/.env" and method == "GET")
                                or (stage == "discovery" and path == "/")):
                            return response(status)
                        return response(200 if path == "/.env" else 404)
                    with self.assertRaises(HTTPStop):
                        self.scan(request)
                    self.assertEqual(len(calls), {"baseline": 1, "head": 2, "get": 3, "discovery": 37}[stage])

    def test_exclusions_apply_to_fixed_paths_and_discovery(self):
        fake = Mock(return_value=response(404))
        self.scan(fake, ("/.env", "/.git", "/api", "/_next"))
        self.assertFalse(any(call.args[2].startswith(("/.env", "/.git", "/api", "/_next"))
                             for call in fake.call_args_list))
        fake.reset_mock()
        with self.assertRaises(ToolError):
            self.scan(fake, ("/",))
        fake.assert_not_called()

    def test_cors_reflects_arbitrary_origin_with_credentials_is_flagged(self):
        def request(host, method, path, **kwargs):
            origin = (kwargs.get("headers") or {}).get("Origin")
            if path == "/" and origin:
                return 200, {"content-type": ["text/html"], "content-length": ["2"],
                             "access-control-allow-origin": [origin],
                             "access-control-allow-credentials": ["true"]}, b"ok"
            return response(200, "text/html", b"<html>Welcome</html>")
        records, findings = self.scan(request)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "high")
        self.assertEqual(findings[0]["verification"], "confirmed")
        self.assertTrue(any(item["kind"] == "cors" and item["exposed"] for item in records))

    def test_cors_wildcard_without_credentials_is_not_flagged(self):
        def request(host, method, path, **kwargs):
            if path == "/" and (kwargs.get("headers") or {}).get("Origin"):
                return 200, {"content-type": ["text/html"], "content-length": ["2"],
                             "access-control-allow-origin": ["*"]}, b"ok"
            return response(200, "text/html", b"<html>Welcome</html>")
        _, findings = self.scan(request)
        self.assertEqual(findings, [])

    def test_cors_fixed_allowlisted_origin_with_credentials_is_not_flagged(self):
        def request(host, method, path, **kwargs):
            if path == "/" and (kwargs.get("headers") or {}).get("Origin"):
                return 200, {"content-type": ["text/html"], "content-length": ["2"],
                             "access-control-allow-origin": ["https://trusted-partner.invalid"],
                             "access-control-allow-credentials": ["true"]}, b"ok"
            return response(200, "text/html", b"<html>Welcome</html>")
        _, findings = self.scan(request)
        self.assertEqual(findings, [])

    def test_cors_non_2xx_probe_response_is_not_flagged(self):
        def request(host, method, path, **kwargs):
            if path == "/" and (kwargs.get("headers") or {}).get("Origin"):
                return 404, {"content-type": ["text/html"]}, b""
            return response(200, "text/html", b"<html>Welcome</html>")
        _, findings = self.scan(request)
        self.assertEqual(findings, [])

    def test_open_redirect_with_marker_in_location_is_flagged(self):
        from urllib.parse import parse_qs, urlsplit

        def request(host, method, path, **kwargs):
            query = parse_qs(urlsplit(path).query)
            if "next" in query:
                return 302, {"location": [query["next"][0]]}, b""
            return response(200, "text/html", b"<html>Welcome</html>")
        records, findings = self.scan(request)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "medium")
        self.assertTrue(any(item["kind"] == "open_redirect" and item["exposed"] for item in records))

    def test_redirect_to_unrelated_location_is_not_flagged(self):
        def request(host, method, path, **kwargs):
            if "?" in path:
                return 302, {"location": ["/login"]}, b""
            return response(200, "text/html", b"<html>Welcome</html>")
        _, findings = self.scan(request)
        self.assertEqual(findings, [])

    def test_non_redirect_status_on_probe_is_not_flagged(self):
        def request(host, method, path, **kwargs):
            if "?" in path:
                return 404, {}, b""
            return response(200, "text/html", b"<html>Welcome</html>")
        _, findings = self.scan(request)
        self.assertEqual(findings, [])

    def test_redirect_probe_network_failure_is_not_flagged_or_raised(self):
        def request(host, method, path, **kwargs):
            if "?" in path:
                raise OSError("connection reset")
            return response(200, "text/html", b"<html>Welcome</html>")
        _, findings = self.scan(request)
        self.assertEqual(findings, [])

    def test_discovery_is_bounded_same_origin_and_deduplicated(self):
        body = b"".join(f'<script src="/_next/static/chunk-{i}.js"></script>'.encode() for i in range(6))
        body += b'<script src="https://outside.invalid/map.js"></script>'
        fake = Mock(side_effect=lambda host, method, path, **kwargs:
                    response(200, "text/html", body) if path == "/" else response(404))
        self.scan(fake)
        maps = [call.args[2] for call in fake.call_args_list if call.args[2].endswith(".map")]
        self.assertEqual(maps, [f"/_next/static/chunk-{i}.js.map" for i in range(3)])
        discovery = next(call for call in fake.call_args_list if call.args[2] == "/")
        self.assertEqual(discovery.kwargs["body_limit"], 262144)
