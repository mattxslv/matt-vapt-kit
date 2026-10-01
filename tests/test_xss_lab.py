"""Opt-in real-browser lab. The only server is a temporary IPv4 loopback fixture."""
import json
import os
import secrets
import threading
import unittest
from dataclasses import asdict
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlencode, urlsplit

from fixtures.xss_app import Handler
from vaptkit.xss import XssEvidence, evaluate_xss

CASES = json.loads((Path(__file__).parent / "fixtures/xss_cases.json").read_text())["cases"]


@unittest.skipUnless(os.environ.get("MVK_RUN_XSS_LAB") == "1", "opt-in loopback-only browser XSS lab")
class XssBrowserLab(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from playwright.sync_api import sync_playwright
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.server.records = {}
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.origin = f"http://127.0.0.1:{cls.server.server_port}"
        def close_server():
            cls.server.shutdown()
            cls.server.server_close()
            cls.thread.join(timeout=5)
            cls.server.records.clear()
        cls.addClassCleanup(close_server)
        cls.playwright = sync_playwright().start()
        cls.addClassCleanup(cls.playwright.stop)
        cls.browser = cls.playwright.chromium.launch()
        cls.addClassCleanup(cls.browser.close)

    def attempt(self, case):
        marker = "fixture_" + secrets.token_hex(12)
        payload = f'<img src="/missing" onerror="window.__mvk_xss__=\'{marker}\'">'
        with self.browser.new_context(service_workers="block", accept_downloads=False) as context:
            outside_requests = []
            def route_request(route):
                parsed = urlsplit(route.request.url)
                allowed = (f"{parsed.scheme}://{parsed.netloc}" == self.origin
                           and parsed.path in ("/control", "/view", "/missing")
                           and route.request.method == "GET")
                if allowed:
                    route.continue_()
                else:
                    outside_requests.append(True)
                    route.abort()
            context.route("**/*", route_request)
            context.add_init_script(
                "window.__mvk_csp_blocked__ = false;"
                "document.addEventListener('securitypolicyviolation', () => { window.__mvk_csp_blocked__ = true; });"
            )
            page = context.new_page()
            browser_errors = []
            page.on("pageerror", lambda error: browser_errors.append(True))
            control_url = self.origin + "/control" + ("?broken=1" if case.get("broken_control") else "")
            page.goto(control_url, wait_until="networkidle")
            control = page.evaluate("window.__mvk_control__ === true")
            query = {"kind": case["kind"], "mode": case["mode"]}
            if case["kind"] == "stored":
                response = context.request.post(self.origin + "/store", data={"value": payload})
                self.assertEqual(response.status, 200)
                query["id"] = response.json()["id"]
            else:
                query["value"] = payload
            url = self.origin + "/view?" + urlencode(query)
            response = page.goto(url, wait_until="networkidle")
            self.assertIsNotNone(response)
            evidence = XssEvidence(
                status=response.status,
                html_assessed=response.headers.get("content-type", "").startswith("text/html"),
                execution_observed=page.evaluate("(marker) => window.__mvk_xss__ === marker", marker),
                reflection_observed=marker in page.content(),
                csp_blocked=page.evaluate("window.__mvk_csp_blocked__ === true"),
                browser_failed=bool(browser_errors),
                same_document=page.url == url,
            )
            self.assertEqual(outside_requests, [])
            self.assertNotIn(marker, json.dumps(asdict(evidence)))
            self.assertNotIn(payload, json.dumps(asdict(evidence)))
            return control, evidence

    def test_manifest_requires_execution_not_reflection(self):
        self.assertEqual(len(CASES), 12)
        self.assertEqual(len({case["id"] for case in CASES}), len(CASES))
        counts = {"confirmed": 0, "not_reproduced": 0, "inconclusive": 0}
        for case in CASES:
            with self.subTest(case=case["id"]):
                self.server.records = {}
                controls, attempts = zip(*(self.attempt(case) for _ in range(2)))
                outcome = evaluate_xss(all(controls), list(attempts))
                counts[outcome] += 1
                self.assertEqual(outcome, case["expected"])
                if case["mode"] == "escaped":
                    self.assertTrue(all(item.reflection_observed for item in attempts))
                    self.assertFalse(any(item.execution_observed for item in attempts))
                if case["mode"] == "csp":
                    self.assertTrue(all(item.csp_blocked for item in attempts))
                if case["kind"] == "stored":
                    self.assertEqual(len(self.server.records), 2)
                self.server.records.clear()
        self.assertEqual(counts, {"confirmed": 3, "not_reproduced": 3, "inconclusive": 6})
        print("\nLoopback browser XSS lab: " + json.dumps(counts, sort_keys=True))
