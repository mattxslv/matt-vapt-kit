"""Opt-in browser walkthrough with a temporary localhost server and synthetic data."""
import os
import socket
import tempfile
import threading
import unittest
from pathlib import Path

import yaml

@unittest.skipUnless(os.environ.get("MVK_RUN_DASHBOARD_BROWSER") == "1", "opt-in dashboard browser walkthrough")
class DashboardBrowserTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from playwright.sync_api import sync_playwright
        from werkzeug.serving import WSGIRequestHandler, make_server
        from vaptkit.dashboard import create_app
        cls.directory = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.directory.cleanup)
        root = Path(cls.directory.name)
        projects = root / "projects"
        projects.mkdir()
        config = {
            "schema_version": 1, "project": "browser-fixture",
            "target": {"environment": "staging", "url": "https://staging.example.invalid",
                       "allowed_hosts": ["staging.example.invalid"], "verification": "pending"},
            "scope": {"api_prefixes": ["/api/"], "excluded_prefixes": [],
                      "roles": ["lead-evaluator", "service-provider"]},
            "credentials": {},
            "role_testing": {
                "adapter": "dtap-cookie-v1",
                "accounts": [
                    {"id": "lead-evaluator", "role": "lead-evaluator",
                     "email_env": "FIXTURE_LEAD_EMAIL", "password_env": "DTAP_QA_PASSWORD"},
                    {"id": "service-provider", "role": "service-provider",
                     "email_env": "FIXTURE_PROVIDER_EMAIL", "password_env": "DTAP_QA_PASSWORD"},
                ],
                "routes": [{"path": "/api/fixture", "allowed_roles": ["lead-evaluator"],
                            "response_shape": {"data": "array"}}],
            },
        }
        (projects / "fixture.yml").write_text(yaml.safe_dump(config))
        with socket.socket() as reserved:
            reserved.bind(("127.0.0.1", 0))
            port = reserved.getsockname()[1]
        cls.origin = f"http://127.0.0.1:{port}"
        cls.app = create_app(projects, root / "data", origin=cls.origin)
        class QuietHandler(WSGIRequestHandler):
            def log(self, *args, **kwargs):
                pass
        cls.server = make_server("127.0.0.1", port, cls.app, threaded=True, request_handler=QuietHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        def cleanup():
            cls.app.extensions["jobs"].close()
            cls.server.shutdown()
            cls.server.server_close()
            cls.thread.join(timeout=5)
        cls.addClassCleanup(cleanup)
        cls.playwright = sync_playwright().start()
        cls.addClassCleanup(cls.playwright.stop)
        cls.browser = cls.playwright.chromium.launch()
        cls.addClassCleanup(cls.browser.close)

    def test_demo_download_and_scope_flow(self):
        from playwright.sync_api import expect
        with self.browser.new_context(accept_downloads=True) as context:
            page = context.new_page()
            errors = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.goto(self.origin)
            expect(page.get_by_role("heading", name="Define before you run.")).to_be_visible()
            page.get_by_role("button", name="Create sample report").click()
            expect(page.get_by_role("heading", name="Your evidence is ready.")).to_be_visible(timeout=60000)
            expect(page.get_by_text("Demo only. The findings below")).to_be_visible()
            with page.expect_download() as event:
                page.get_by_role("button", name="Download PDF").click()
            download = event.value
            self.assertTrue(Path(download.path()).read_bytes().startswith(b"%PDF-"))
            page.get_by_role("button", name="Set up another assessment").click()
            page.get_by_label("Project", exact=True).select_option("fixture.yml")
            page.get_by_label("Assessment", exact=True).select_option("roles")
            page.get_by_label("Authorized owner").fill("Synthetic operator")
            page.get_by_label("lead-evaluator (lead-evaluator)", exact=True).check()
            page.get_by_label("service-provider (service-provider)", exact=True).check()
            page.get_by_role("button", name="Check prerequisites").click()
            expect(page.get_by_role("heading", name="Your approval, in plain sight.")).to_be_visible(timeout=15000)
            password = page.get_by_label("QA password (DTAP_QA_PASSWORD)")
            password.fill("SYNTHETIC_BROWSER_PASSWORD")
            self.assertEqual(password.get_attribute("type"), "password")
            page.get_by_role("button", name="Back to scope").click()
            self.assertEqual(page.locator('#credential-fields input').count(), 0)
            self.assertEqual(errors, [])
            for width in (1280, 390):
                page.set_viewport_size({"width": width, "height": 900})
                self.assertTrue(page.evaluate("document.documentElement.scrollWidth <= innerWidth"))
