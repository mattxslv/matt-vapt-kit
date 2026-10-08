import json
import tempfile
import unittest
from datetime import date, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from vaptkit.live import run_read_only, staging_counts, standing_approval
from vaptkit.process import ToolError


class StandingApprovalTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.config = Path(self._tmp.name) / "demo.vapt.yml"
        self.config.write_text("project: demo\n")

    def write(self, text):
        (Path(self._tmp.name) / "demo.standing-approval.yml").write_text(text)

    def test_missing_file_means_no_live_checks(self):
        self.assertIsNone(standing_approval(self.config))
        self.assertIsNone(standing_approval(None))

    def test_active_until_and_including_the_expiry_date(self):
        self.write(f"approved_by: owner\nexpires_on: {date.today().isoformat()}\n")
        self.assertTrue(standing_approval(self.config)["active"])

    def test_expired_approval_is_returned_inactive(self):
        self.write(f"approved_by: owner\nexpires_on: {(date.today() - timedelta(days=1)).isoformat()}\n")
        self.assertFalse(standing_approval(self.config)["active"])

    def test_incomplete_record_is_rejected(self):
        self.write("approved_by: owner\n")
        with self.assertRaises(ToolError):
            standing_approval(self.config)


class RunReadOnlyTests(unittest.TestCase):
    def test_builds_a_one_hour_read_only_approval_from_the_standing_record(self):
        captured = {}

        def fake_assess(config, approval, output):
            captured.update(approval)
            path = Path(output) / "assessment.json"
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps({"findings": [], "errors": [], "exposure": [], "observations": []}))
            return path, 0

        config = {"project": "demo", "target": {"url": "https://staging.example.invalid"},
                  "scope": {"excluded_prefixes": []}}
        with tempfile.TemporaryDirectory() as directory, patch("vaptkit.live.assess", side_effect=fake_assess):
            run_read_only(config, {"approved_by": "owner", "active": True}, Path(directory) / "staging")
        window = datetime.fromisoformat(captured["expires_at"]) - datetime.fromisoformat(captured["starts_at"])
        self.assertEqual(window, timedelta(hours=1))
        self.assertEqual(captured["approved_by"], "owner")
        self.assertEqual(captured["method"], "HEAD")
        self.assertTrue(captured["exposure_checks"])

    def test_refuses_to_run_on_an_expired_approval(self):
        with self.assertRaises(ToolError):
            run_read_only({}, {"approved_by": "owner", "active": False}, Path("/nonexistent"))

    def test_counts_only_paths_that_were_actually_exposed(self):
        counts = staging_counts({"findings": [], "errors": [],
                                 "exposure": [{"path": "/.env", "exposed": True}, {"path": "/x", "exposed": False}]})
        self.assertEqual(counts["exposed"], 1)
