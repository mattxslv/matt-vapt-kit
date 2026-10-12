import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vaptkit.process import ToolError
from vaptkit.report import conclusion, generate, render, validate_result

ROOT = Path(__file__).resolve().parents[1]


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.source = ROOT / "tests/fixtures/assessment.json"
        self.result = json.loads(self.source.read_text())

    def test_fixture_valid_and_labeled(self):
        validate_result(self.result)
        document = render(self.result)
        self.assertIn("SYNTHETIC EXAMPLE", document)
        self.assertIn("Not tested", document)
        self.assertIn("not a CERT-PH", document)
        self.assertNotIn("No leaks", document)

    def test_html_escaped(self):
        self.result["findings"][0]["impact"] = '<script>fetch("https://evil.example")</script>'
        document = render(self.result)
        self.assertNotIn("<script>", document)
        self.assertIn("&lt;script&gt;", document)
        self.assertIn("default-src 'none'", document)

    def test_cors_exposure_record_renders_without_error(self):
        self.result["exposure"] = [
            {"path": "/", "kind": "cors", "status": 200, "exposed": True, "signature": True}]
        document = render(self.result)
        self.assertIn("Cross-origin resource sharing", document)
        self.assertIn("Exposed (signature matched)", document)

    def test_open_redirect_exposure_record_renders_without_error(self):
        self.result["exposure"] = [
            {"path": "/?next=https%3A%2F%2Fevil.invalid%2F", "kind": "open_redirect",
             "status": 302, "exposed": True, "signature": True}]
        document = render(self.result)
        self.assertIn("Unvalidated redirect target", document)
        self.assertIn("Exposed (signature matched)", document)

    def test_conclusions(self):
        category = "data_exposure"
        self.assertEqual(conclusion(self.result, category), "Not tested")
        self.result["coverage"][category] = "tested"
        self.assertEqual(conclusion(self.result, category), "Not observed in tested scope")
        self.result["status"] = "incomplete"
        self.assertEqual(conclusion(self.result, category), "Not tested")
        finding = self.result["findings"][0]
        finding.update(category=category, verification="suspected")
        self.assertEqual(conclusion(self.result, category), "Suspected")
        finding["verification"] = "confirmed"
        self.assertEqual(conclusion(self.result, category), "Confirmed")

    def test_unreviewed_data_cannot_export(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ToolError):
                generate(self.source, Path(directory) / "out", reviewed=False)
            self.assertFalse((Path(directory) / "out").exists())

    def test_html_export_offline_and_private(self):
        with tempfile.TemporaryDirectory() as directory, patch(
            "socket.socket", side_effect=AssertionError("No external requests")
        ):
            path = generate(self.source, Path(directory) / "out", reviewed=True, html_only=True)
            self.assertTrue(path.is_file())
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(ToolError):
                generate(self.source, path.parent, reviewed=True, html_only=True)

    def test_unknown_sensitive_fields_rejected(self):
        self.result["cookies"] = "PRIVATE_SENTINEL"
        with self.assertRaises(ToolError) as error:
            validate_result(self.result)
        self.assertNotIn("PRIVATE_SENTINEL", str(error.exception))

    def test_incomplete_redirect_is_not_a_header_finding(self):
        self.result["status"] = "incomplete"
        self.result["observations"][0]["status"] = 302
        self.result["findings"] = []
        self.result["errors"] = [{"path": "/", "kind": "http", "message": "HTTP 302: redirect not followed."}]
        document = render(self.result)
        self.assertIn("Assessment incomplete. Resolve", document)
        self.assertIn("Not assessed (non-2xx response)", document)
        self.assertNotIn("<td>Not observed</td>", document)

    def test_completed_report_rejects_gaps_and_errors(self):
        for change in (
            lambda r: r.update(observations=[]),
            lambda r: r["observations"][0].update(status=302),
            lambda r: r.update(approved_paths=["/", "/missing"]),
            lambda r: r.update(errors=[{"path": "/", "kind": "transport", "message": "Timeout"}]),
        ):
            result = copy.deepcopy(self.result)
            result["status"] = "completed"
            change(result)
            with self.assertRaises(ToolError):
                validate_result(result)

    def test_cert_style_structure_and_ownership_markers(self):
        document = render(self.result)
        for heading in ("1 EXECUTIVE SUMMARY", "1.2 Scope", "2 KEY FINDINGS", "3 RECOMMENDATION",
                        "4 VULNERABILITY FINDINGS", "4.1 Reconnaissance", "4.2 Vulnerability Identification",
                        "4.3 Attack and Exploitation", "5 CLEAN-UP", "6 DISCLAIMER",
                        "APPENDIX A", "APPENDIX B", "APPENDIX C", "APPENDIX D"):
            self.assertIn(heading, document)
        self.assertIn("MVK-DEMONSTRATION-20261001-000000", document)
        self.assertIn('<div class="watermark" aria-hidden="true">MVK</div>', document)
        self.assertIn("NOT ISSUED BY CERT-PH", document)
        self.assertIn("TLP:AMBER+STRICT", document)
        self.assertIn("Low (not scored)", document)
        self.assertIn('A02: Security Misconfiguration</td><td class="num">1', document)
        self.assertNotIn("\u2014", document)

    def test_cvss_must_match_severity_and_version(self):
        finding = self.result["findings"][0]
        finding["cvss"] = {"version": "3.1", "score": 3.1, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N"}
        self.assertIn("Low (3.1)", render(self.result))
        for change in ({"score": 7.5}, {"score": 3.15}, {"vector": "CVSS:4.0/AV:N"}):
            bad = copy.deepcopy(self.result)
            bad["findings"][0]["cvss"].update(change)
            with self.assertRaises(ToolError):
                validate_result(bad)

    def test_unmapped_data_exposure_is_counted_honestly(self):
        self.result["findings"][0]["category"] = "data_exposure"
        self.assertIn("Not mapped to a category</td><td class=\"num\">1", render(self.result))
        self.result["findings"][0]["owasp"] = "A06"
        self.assertIn('A06: Insecure Design</td><td class="num">1', render(self.result))

    def test_labels_are_escaped_and_bounded(self):
        document = render(self.result, prepared_by="<b>Matt</b>", agency="DICT & MISS", tlp="RED")
        self.assertIn("&lt;b&gt;Matt&lt;/b&gt;", document)
        self.assertIn("DICT &amp; MISS", document)
        self.assertIn("TLP:RED", document)
        for kwargs in ({"prepared_by": "x\nInjected"}, {"agency": "a" * 121}, {"tlp": "PURPLE"}):
            with self.assertRaises(ToolError):
                render(self.result, **kwargs)

    def test_head_only_cannot_claim_untested_coverage(self):
        for profile in ("unauthenticated-head-only", "bearer-head-only"):
            self.result["profile"] = profile
            self.result["coverage"]["data_exposure"] = "tested"
            with self.assertRaises(ToolError):
                validate_result(self.result)

    def test_exposure_retest_and_verification_render_without_raw_content(self):
        self.result["profile"] = "unauthenticated-exposure"
        self.result["exposure"] = [
            {"path": "/.git/HEAD", "kind": "vcs", "status": 200, "exposed": True, "signature": True},
            {"path": "/.env", "kind": "secret_file", "status": 404, "exposed": False, "signature": None},
        ]
        self.result["requests"] = [{"method": "GET", "path": "/.git/HEAD", "status": 206}]
        self.result["retest"] = [{"path": "/", "title": "<old>", "status": "not_rechecked"}]
        self.result["findings"][0]["evidence"] = "<repeat>"
        validate_result(self.result)
        document = render(self.result)
        for text in ("Public exposure checks", "Retest Results", "GET https://", "&lt;repeat&gt;",
                     "&lt;old&gt;", "No exposure confirmed", "HTTP HEAD and bounded GET"):
            self.assertIn(text, document)
        self.assertNotIn("sent only HTTP HEAD", document)
