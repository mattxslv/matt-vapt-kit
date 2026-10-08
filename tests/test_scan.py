import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from rich.console import Console

from vaptkit.process import ToolError, git
from vaptkit.scan import LOADING_WORDS, LoadingMessage, duration, path_link, print_header, recap, scan, static_summary


class ScanTests(unittest.TestCase):
    def test_header_centers_and_fits_wide_and_narrow_terminals(self):
        for width in (30, 40, 80, 120):
            stream = io.StringIO()
            console = Console(file=stream, force_terminal=False, width=width)
            print_header(console)
            lines = stream.getvalue().splitlines()
            self.assertTrue(all(len(line) <= width for line in lines))
            self.assertNotIn("anti vince vulnerability", stream.getvalue())
            self.assertNotIn("Matt VAPT Kit", stream.getvalue())
            self.assertNotIn("╭", stream.getvalue())
            self.assertNotIn("│", stream.getvalue())
            self.assertNotIn("COMMITTED-CODE CHECKS", stream.getvalue())
            self.assertNotIn("to prevent spilling the beans :D", stream.getvalue())
            self.assertNotIn("\x1b", stream.getvalue())

    def test_loading_message_shows_word_and_elapsed_time_without_fake_progress(self):
        with patch("vaptkit.scan.time.monotonic", return_value=10), patch(
            "vaptkit.scan.random.choice", return_value="Topsy-turvying"
        ), patch("vaptkit.scan.random.randrange", return_value=0):
            message = LoadingMessage("Static rules")
        self.assertGreaterEqual(len(LOADING_WORDS), 60)
        self.assertEqual(len(set(LOADING_WORDS)), len(LOADING_WORDS))
        for now, seconds in ((10, "0s"), (47, "37s")):
            with patch("vaptkit.scan.time.monotonic", return_value=now):
                rendered = list(message.__rich_console__(None, None))
                self.assertEqual(len(rendered), 1)
                stream = io.StringIO()
                Console(file=stream, force_terminal=False, width=80).print(rendered[0])
                text = stream.getvalue()
            self.assertIn("Topsy-turvying…", text)
            self.assertIn(f"({seconds} · Static rules)", text)
            self.assertNotIn("%", text)

    def test_loading_message_tracks_the_real_step_without_fake_code(self):
        with patch("vaptkit.scan.time.monotonic", return_value=0), patch(
            "vaptkit.scan.random.choice", return_value="Digging"
        ):
            message = LoadingMessage("3 / 4  Static rules")
            stream = io.StringIO()
            Console(file=stream, force_terminal=False, width=80).print(next(iter(message.__rich_console__(None, None))))
        lines = stream.getvalue().splitlines()
        self.assertIn("Digging…", lines[0])
        self.assertIn("(0s · Static rules)", lines[0])
        self.assertIn("step 3 of 4", lines[1])
        self.assertEqual(lines[1].count("━"), 15)
        self.assertEqual(len(lines), 2)

    def test_recap_summarizes_findings_and_suggests_first_step(self):
        rows = [{"check": f"{n} / 4  {name}", "status": status, "detail": ""} for n, name, status in (
            (1, "Secret history", "REVIEW"), (2, "Dependency audit", "REVIEW"),
            (3, "Static rules", "NOT RUN"), (4, "API authentication review", "REVIEW"))]
        text = recap("DTAP", rows, {"leaks": 74, "vulnerabilities": 13, "severity": "10 moderate | 3 high",
                                    "high": True, "routes": 16})
        self.assertIn("DTAP has 74 possible secrets", text)
        self.assertIn("13 vulnerable packages (10 moderate | 3 high)", text)
        self.assertIn("16 API routes", text)
        self.assertIn("Static rules did not run", text)
        self.assertIn("Next, go through the leaked secrets first", text)
        clean = recap("demo", [{"check": "1 / 4  Secret history", "status": "DONE", "detail": ""}], {})
        self.assertIn("Nothing was flagged", clean)

    def test_duration_reads_like_minutes_and_seconds(self):
        self.assertEqual(duration(20.4), "20s")
        self.assertEqual(duration(125), "2m 5s")

    def test_clickable_paths_are_encoded_and_plain_mode_has_no_escape_codes(self):
        path = self.root / "directory with spaces [demo]"
        link = path_link(path)
        self.assertEqual(link.style.link, path.resolve().as_uri())
        stream = io.StringIO()
        console = Console(file=stream, force_terminal=True)
        console.print(link)
        self.assertIn("\x1b]8;", stream.getvalue())
        self.assertIn("%20", stream.getvalue())
        stream.seek(0); stream.truncate(0)
        console.print(path_link(path, enabled=False))
        self.assertNotIn("\x1b", stream.getvalue())
        self.assertIn("directory with spaces [demo]", stream.getvalue())

    def test_static_summary_keeps_locations_but_never_source_snippets(self):
        raw = json.dumps({"results": [{"path": "/src/example.ts", "check_id": "fixture.rule",
                                      "start": {"line": 12},
                                      "extra": {"lines": "PRIVATE_SOURCE_SENTINEL"}}], "errors": []})
        rows = static_summary(raw)
        self.assertEqual(rows, [{"path": "example.ts", "rule": "fixture.rule", "line": 12,
                                 "verification": "suspected"}])
        self.assertNotIn("PRIVATE_SOURCE_SENTINEL", json.dumps(rows))
        for invalid in ('{"results":[],"errors":[{"message":"PRIVATE"}]}', "PRIVATE", '{"results":null}'):
            with self.assertRaises(ToolError) as error:
                static_summary(invalid)
            self.assertNotIn("PRIVATE", str(error.exception))

    def test_many_static_matches_are_grouped_without_losing_locations(self):
        raw = json.dumps({"results": [
            {"path": f"/src/file-{index}.js", "check_id": "rules.fixture",
             "start": {"line": index + 1}, "extra": {"lines": "PRIVATE_CODE"}}
            for index in range(69)
        ], "errors": []})
        real_run = subprocess.run
        def process(command, **kwargs):
            if command[:2] == ["docker", "info"]:
                return subprocess.CompletedProcess(command, 0, stdout="")
            if command[:2] == ["docker", "run"]:
                self.assertIn("--json", command)
                return subprocess.CompletedProcess(command, 1, stdout=raw, stderr="")
            return real_run(command, **kwargs)
        with patch("vaptkit.scan.shutil.which", return_value="/fixture/docker"), patch(
            "vaptkit.scan.subprocess.run", side_effect=process
        ), patch("vaptkit.scan.scan_history", return_value=None), patch(
            "vaptkit.scan.audit_commit", return_value=None
        ), patch("vaptkit.scan.review", return_value={"summary": {"handlers": 0}, "findings": []}):
            code = scan(self.repo, output=self.root / "out", console=self.console)
        self.assertEqual(code, 1)
        self.assertIn("69 matches", self.stream.getvalue())
        self.assertIn("+ 66 more locations", self.stream.getvalue())
        self.assertNotIn("file-68.js", self.stream.getvalue())
        saved = (self.root / "out/static-findings.json").read_text()
        self.assertEqual(len(json.loads(saved)["findings"]), 69)
        self.assertNotIn("PRIVATE_CODE", saved + self.stream.getvalue())

    def test_partial_static_results_survive_processing_errors_and_nonzero_exit(self):
        raw = json.dumps({"results": [
            {"path": "/src/fixture.js", "check_id": "fixture.rule", "start": {"line": 3}}
        ], "errors": [{"type": "ParseError", "message": "PRIVATE_CODE"}]})
        real_run = subprocess.run
        def process(command, **kwargs):
            if command[:2] == ["docker", "info"]:
                return subprocess.CompletedProcess(command, 0)
            if command[:2] == ["docker", "run"]:
                return subprocess.CompletedProcess(command, 3, stdout=raw, stderr="PRIVATE_CODE")
            return real_run(command, **kwargs)
        with patch("vaptkit.scan.shutil.which", return_value="/fixture/docker"), patch(
            "vaptkit.scan.subprocess.run", side_effect=process
        ), patch("vaptkit.scan.scan_history", return_value=None), patch(
            "vaptkit.scan.audit_commit", return_value=None
        ), patch("vaptkit.scan.review", return_value={"summary": {"handlers": 0}, "findings": []}):
            code = scan(self.repo, output=self.root / "out", console=self.console)
        self.assertEqual(code, 1)
        saved = (self.root / "out/static-findings.json").read_text()
        result = json.loads(saved)
        self.assertEqual(len(result["findings"]), 1)
        self.assertEqual(result["processing_errors"], [{"type": "ParseError"}])
        self.assertEqual(result["status"], "incomplete")
        self.assertIn("1 static matches retained", self.stream.getvalue())
        self.assertNotIn("PRIVATE_CODE", saved + self.stream.getvalue())

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

    def test_plain_mode_does_not_start_animation(self):
        with patch("vaptkit.scan.shutil.which", return_value=None), patch(
            "vaptkit.scan.audit_commit", return_value=None
        ), patch("vaptkit.scan.review", return_value={"summary": {"handlers": 0}, "findings": []}), patch.object(
            self.console, "status"
        ) as status:
            scan(self.repo, output=self.root / "out", console=self.console, plain=True)
        status.assert_not_called()

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
