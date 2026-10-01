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
