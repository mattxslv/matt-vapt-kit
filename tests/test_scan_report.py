import json
import tempfile
import unittest
from pathlib import Path

from vaptkit.process import ToolError
from vaptkit.scan_report import render_scan, write_scan_report


class ScanReportTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.folder = Path(self._tmp.name) / "scan-20261008-010203-abcdef"
        self.folder.mkdir()
        (self.folder / "summary.json").write_text(json.dumps({
            "kind": "repository-scan", "revision": "a" * 40, "finished_at": "2026-10-08T01:02:03+00:00",
            "project": "demo-app", "facts": {"leaks": 3},
            "recap": "demo-app has 3 possible secrets in its Git history.",
            "checks": [{"check": "1 / 4  Secret history", "status": "REVIEW", "detail": "3 leaks <b>found</b>"}],
            "not_tested": ["live staging"],
        }))
        (self.folder / "static-findings.json").write_text(json.dumps({"findings": [
            {"rule": "rules.eval-usage", "path": "scripts/seed.js", "line": 8}]}))
        (self.folder / "route-review.json").write_text(json.dumps({"routes": [
            {"path": "/api/users", "file": "app/api/users/route.ts",
             "handlers": [{"method": "GET", "authentication": False}, {"method": "POST", "authentication": True}]}]}))

    def test_report_lists_recap_leak_count_static_matches_and_unauthenticated_handlers(self):
        document = render_scan(self.folder)
        for expected in ("demo-app", "3 possible secrets", "rules.eval-usage", "scripts/seed.js",
                         "/api/users", "MVK-SCAN-20261008-010203-abcdef", "Live staging"):
            self.assertIn(expected, document)
        self.assertEqual(document.count("<code>/api/users</code>"), 1)

    def test_scan_output_is_escaped(self):
        self.assertIn("3 leaks &lt;b&gt;found&lt;/b&gt;", render_scan(self.folder))

    def test_html_only_writes_report_into_the_scan_folder(self):
        html, pdf = write_scan_report(self.folder, html_only=True)
        self.assertEqual(html, self.folder / "report.html")
        self.assertIsNone(pdf)
        self.assertIn("Repository Scan", html.read_text())

    def test_folder_without_a_repository_scan_is_rejected(self):
        with self.assertRaises(ToolError):
            render_scan(Path(self._tmp.name))
