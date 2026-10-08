import json
import tempfile
import unittest
from pathlib import Path

from vaptkit.certph import collect_tickets, render_markdown


class CertphExportTests(unittest.TestCase):
    def folder(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        folder = Path(directory.name)
        (folder / "summary.json").write_text(json.dumps({"project": "demo", "branch": "main", "revision": "a" * 40}))
        (folder / "route-review.json").write_text(json.dumps({"findings": [
            {"title": "Handler has no authentication check", "severity": "high", "verification": "suspected",
             "owasp": "A01", "method": "PUT", "path": "/api/profile", "impact": "PUT handler. No session check.",
             "remediation": "Add a session check."}]}))
        (folder / "static-findings.json").write_text(json.dumps({"findings": [
            {"rule": "rules.tls-verification-disabled", "path": "lib/x.ts", "line": 5, "runtime": True},
            {"rule": "rules.tls-verification-disabled", "path": "scripts/y.js", "line": 2, "runtime": False}]}))
        (folder / "dependency-audit.json").write_text(json.dumps({"top": [
            {"package": "lodash", "version": "4.17.20", "severity": "high", "id": "GHSA-1", "scope": "runtime"},
            {"package": "lodash", "version": "4.17.20", "severity": "high", "id": "GHSA-2", "scope": "runtime"},
            {"package": "handlebars", "version": "4.7.0", "severity": "critical", "id": "GHSA-3", "scope": "dev"}]}))
        (folder / "secret-findings.json").write_text(json.dumps({"findings": [
            {"rule": "generic-api-key", "file": "lib/a.ts", "line": 3, "commit": "b" * 12, "placeholder": False},
            {"rule": "generic-api-key", "file": "docs/x.md", "line": 1, "commit": "c" * 12, "placeholder": True}]}))
        return folder

    def test_collects_one_ticket_per_real_finding_grouping_dependency_advisories(self):
        tickets = collect_tickets(self.folder())
        titles = [item["title"] for item in tickets]
        self.assertIn("Handler has no authentication check", titles)
        self.assertIn("Known vulnerabilities in lodash 4.17.20", titles)
        self.assertNotIn("Known vulnerabilities in handlebars 4.7.0", titles)  # dev-only, excluded
        self.assertTrue(any("generic-api-key" in title for title in titles))
        self.assertFalse(any("docs/x.md" in item["component"] for item in tickets))  # placeholder, excluded
        static = [item for item in tickets if item["component"].startswith(("1 location", "2 locations"))]
        self.assertEqual(len(static), 1)  # the two matching static findings are grouped into one ticket
        self.assertIn("1 location", static[0]["component"])
        lodash = next(item for item in tickets if "lodash" in item["title"])
        self.assertIn("GHSA-1", lodash["description"])
        self.assertIn("GHSA-2", lodash["description"])

    def test_most_severe_first(self):
        tickets = collect_tickets(self.folder())
        order = ["critical", "high", "medium", "low", "informational"]
        indices = [order.index(item["severity"]) for item in tickets]
        self.assertEqual(indices, sorted(indices))

    def test_markdown_is_a_valid_table_and_mentions_the_project_and_branch(self):
        text = render_markdown(self.folder())
        self.assertIn("demo", text)
        self.assertIn("(main)", text)
        self.assertIn("| # | Finding |", text)
        rows = [line for line in text.splitlines() if line.startswith("| MVK-")]
        self.assertEqual(len(rows), len(collect_tickets(self.folder())))
        self.assertTrue(all(row.count("|") == 9 for row in rows))

    def test_empty_scan_still_produces_a_readable_table(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        folder = Path(directory.name)
        (folder / "summary.json").write_text(json.dumps({"project": "clean", "revision": "a" * 40}))
        text = render_markdown(folder)
        self.assertIn("No findings to export.", text)
