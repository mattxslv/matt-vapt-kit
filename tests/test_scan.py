import io
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from rich.console import Console

from vaptkit.process import ToolError, git
from vaptkit.scan import scan


class ScanTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        git(self.repo, "init", "-q")
        git(self.repo, "config", "user.name", "Fixture")
        git(self.repo, "config", "user.email", "fixture@example.invalid")
        (self.repo / "package.json").write_text('{"packageManager":"pnpm@10.27.0"}')
        git(self.repo, "add", ".")
        git(self.repo, "commit", "-qm", "Add fixture")
        self.stream = io.StringIO()
        self.console = Console(file=self.stream, force_terminal=False, width=100)

    def test_checks_continue_independently_after_findings_and_use_same_revision(self):
        with patch("vaptkit.scan.shutil.which", return_value="/fixture/docker"), patch(
            "vaptkit.scan.subprocess.run", return_value=SimpleNamespace(returncode=0)
        ), patch("vaptkit.scan.git", side_effect=lambda repo, *args: (
            str(self.repo) if args[0] == "rev-parse" else "package.json"
        )), patch("vaptkit.scan.checked_revision", return_value="a" * 40), patch(
            "vaptkit.scan.scan_history", side_effect=ToolError("Synthetic scanner needs review.")
        ) as history, patch("vaptkit.scan.audit_commit", return_value=None) as audit, patch(
            "vaptkit.scan.scan_static", return_value=None
        ) as static, patch("vaptkit.scan.review", return_value={
            "summary": {"handlers": 3}, "findings": [],
        }) as routes:
            code = scan(self.repo, output=self.root / "out", console=self.console)
        self.assertEqual(code, 1)
        for mock in (history, audit, static):
            self.assertEqual(mock.call_args.args[1], "a" * 40)
        self.assertEqual(routes.call_args.args[2], "a" * 40)
        result = json.loads((self.root / "out/summary.json").read_text())
        self.assertEqual([row["status"] for row in result["checks"]], ["REVIEW", "DONE", "DONE", "DONE"])
        self.assertEqual((self.root / "out/summary.json").stat().st_mode & 0o777, 0o600)
        self.assertIn("Not a live VAPT", self.stream.getvalue())
        self.assertNotIn("\x1b", self.stream.getvalue())

    def test_missing_docker_is_explicit_and_other_checks_still_run(self):
        with patch("vaptkit.scan.shutil.which", return_value=None), patch(
            "vaptkit.scan.scan_history"
        ) as history, patch("vaptkit.scan.scan_static") as static, patch(
            "vaptkit.scan.audit_commit", return_value=None
        ) as audit, patch("vaptkit.scan.review", return_value={"summary": {"handlers": 0}, "findings": []}):
            code = scan(self.repo, output=self.root / "out", console=self.console)
        self.assertEqual(code, 1)
        history.assert_not_called()
        static.assert_not_called()
        audit.assert_called_once()
        self.assertIn("NOT RUN", self.stream.getvalue())

    def test_uncommitted_files_not_used_for_ecosystem_detection(self):
        git(self.repo, "rm", "package.json")
        git(self.repo, "commit", "-qm", "Remove manifests")
        (self.repo / "package.json").write_text('{"private":true}')
        with patch("vaptkit.scan.shutil.which", return_value=None), patch(
            "vaptkit.scan.audit_commit", return_value=None
        ) as audit, patch("vaptkit.scan.review", return_value={"summary": {"handlers": 0}, "findings": []}):
            scan(self.repo, output=self.root / "out", console=self.console)
        audit.assert_not_called()
        self.assertIn("not implemented", self.stream.getvalue())

    def test_existing_output_not_overwritten(self):
        with self.assertRaises(ToolError):
            scan(self.repo, output=self.root, console=self.console)

    def test_cancellation_preserves_partial_summary_and_stops_following_checks(self):
        with patch("vaptkit.scan.shutil.which", return_value=None), patch(
            "vaptkit.scan.audit_commit", side_effect=KeyboardInterrupt
        ), patch("vaptkit.scan.review") as routes:
            with self.assertRaises(KeyboardInterrupt):
                scan(self.repo, output=self.root / "out", console=self.console)
        routes.assert_not_called()
        result = json.loads((self.root / "out/summary.json").read_text())
        self.assertEqual(result["status"], "cancelled")
        self.assertEqual(result["checks"][-1]["status"], "CANCELLED")

    def test_suspected_route_findings_are_preserved_without_becoming_confirmed(self):
        with patch("vaptkit.scan.shutil.which", return_value=None), patch(
            "vaptkit.scan.audit_commit", return_value=None
        ), patch("vaptkit.scan.review", return_value={
            "summary": {"handlers": 1}, "findings": [{"verification": "suspected"}],
        }):
            code = scan(self.repo, output=self.root / "out", console=self.console)
        self.assertEqual(code, 1)
        result = json.loads((self.root / "out/route-review.json").read_text())
        self.assertEqual(result["findings"][0]["verification"], "suspected")
        self.assertIn("not confirmed exploits", " ".join(self.stream.getvalue().split()))
