import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

from vaptkit.process import ToolError, stream
from vaptkit.menu import (
    compare_scans, is_local_target, is_noisy_zap_line, local_url, missing_local_attack_images,
    retry_input, scan_findings, staging_config, staging_recap, available_memory_mb,
)


class StagingConfigTests(unittest.TestCase):
    def test_bare_host_gets_https_scheme_and_matching_allowed_host(self):
        config = staging_config("test.dtap.dict.gov.ph")
        self.assertEqual(config["target"]["url"], "https://test.dtap.dict.gov.ph")
        self.assertEqual(config["target"]["allowed_hosts"], ["test.dtap.dict.gov.ph"])
        self.assertEqual(config["target"]["verification"], "reachable-not-authorized")
        self.assertRegex(config["project"], r"^[a-z][a-z0-9-]{0,63}$")

    def test_full_url_is_reduced_to_its_host(self):
        config = staging_config("https://EXAMPLE.invalid/some/path?x=1")
        self.assertEqual(config["target"]["url"], "https://example.invalid")
        self.assertEqual(config["target"]["allowed_hosts"], ["example.invalid"])

    def test_unparseable_input_raises(self):
        with self.assertRaises(ToolError):
            staging_config("   ")


class LocalTargetTests(unittest.TestCase):
    def test_accepts_localhost_and_loopback_with_scheme_and_port(self):
        self.assertTrue(is_local_target("http://localhost:3000"))
        self.assertTrue(is_local_target("http://127.0.0.1:8080"))

    def test_rejects_remote_hosts_and_missing_port(self):
        self.assertFalse(is_local_target("http://example.com:3000"))
        self.assertFalse(is_local_target("http://localhost"))
        self.assertFalse(is_local_target("localhost:3000"))


class LocalUrlTests(unittest.TestCase):
    def test_accepts_bare_port_host_port_and_full_url(self):
        self.assertEqual(local_url("3000"), "http://localhost:3000")
        self.assertEqual(local_url("localhost:8080"), "http://localhost:8080")
        self.assertEqual(local_url("http://127.0.0.1:5000"), "http://127.0.0.1:5000")

    def test_blank_entry_falls_back_to_default_port(self):
        self.assertEqual(local_url(""), "http://localhost:3000")
        self.assertEqual(local_url("   "), "http://localhost:3000")

    def test_remote_host_or_missing_port_raises(self):
        with self.assertRaises(ToolError):
            local_url("example.com:3000")
        with self.assertRaises(ToolError):
            local_url("localhost")


class RetryInputTests(unittest.TestCase):
    def console(self, *inputs):
        stub = MagicMock()
        stub.input.side_effect = inputs
        return stub

    def test_retries_until_parse_succeeds(self):
        console = self.console("not a port", "example.com:3000", "3000")
        result = retry_input(console, "prompt", local_url)
        self.assertEqual(result, "http://localhost:3000")
        self.assertEqual(console.input.call_count, 3)

    def test_b_cancels_without_calling_parse(self):
        console = self.console("b")
        parse = MagicMock()
        self.assertIsNone(retry_input(console, "prompt", parse))
        parse.assert_not_called()


class StagingRecapTests(unittest.TestCase):
    def result(self, **overrides):
        base = {"findings": [], "exposure": [], "errors": []}
        base.update(overrides)
        return base

    def test_clean_result_says_nothing_flagged(self):
        text = staging_recap(self.result())
        self.assertIn("Nothing was flagged", text)

    def test_confirmed_suspected_and_exposure_are_counted_and_prioritized(self):
        text = staging_recap(self.result(
            findings=[{"verification": "confirmed"}, {"verification": "suspected"}],
            exposure=[{"path": "/.env"}],
            errors=[{"path": "/", "kind": "http", "message": "blocked"}],
        ))
        self.assertIn("1 confirmed", text)
        self.assertIn("1 suspected", text)
        self.assertIn("1 exposed files", text)
        self.assertIn("1 requests that did not complete", text)
        self.assertIn("Next, open assessment.json's exposure section", text)


class StreamTests(unittest.TestCase):
    def test_stream_returns_combined_output_exit_code_and_not_timed_out(self):
        lines = []
        text, code, timed_out = stream(["sh", "-c", "echo one; echo two"], lines.append)
        self.assertEqual(code, 0)
        self.assertEqual(lines, ["one", "two"])
        self.assertEqual(text, "one\ntwo")
        self.assertFalse(timed_out)

    def test_stream_raises_if_command_cannot_start(self):
        with self.assertRaises(ToolError):
            stream(["definitely-not-a-real-executable"], lambda line: None)

    def test_stream_kills_slow_command_and_calls_on_timeout(self):
        called = []
        text, code, timed_out = stream(
            ["sh", "-c", "echo start; sleep 5; echo done"],
            lambda line: None, timeout=0.2, on_timeout=lambda: called.append(True),
        )
        self.assertTrue(timed_out)
        self.assertEqual(called, [True])
        self.assertIn("start", text)
        self.assertNotIn("done", text)
        self.assertNotEqual(code, 0)

class AvailableMemoryTests(unittest.TestCase):
    def test_reads_mem_available_in_mib_from_proc_meminfo(self):
        from unittest.mock import mock_open, patch
        from vaptkit.menu import available_memory_mb
        content = "MemTotal:       16000000 kB\nMemAvailable:    4194304 kB\n"
        with patch("builtins.open", mock_open(read_data=content)):
            self.assertEqual(available_memory_mb(), 4096)

    def test_returns_none_when_proc_meminfo_is_unavailable(self):
        from unittest.mock import patch
        from vaptkit.menu import available_memory_mb
        with patch("builtins.open", side_effect=OSError):
            self.assertIsNone(available_memory_mb())

class ZapNoiseFilterTests(unittest.TestCase):
    def test_drops_java_boot_and_logger_lines(self):
        for line in (
            "Found Java version 17.0.20",
            "Available memory: 17818 MB",
            "Using JVM args: -Xmx4454m",
            "876 [main] INFO  org.parosproxy.paros.Constant - Copying default configuration",
        ):
            self.assertTrue(is_noisy_zap_line(line), line)

    def test_keeps_findings_and_errors(self):
        for line in (
            "WARN-NEW: Missing header [10021] x 3",
            "FAIL-NEW: 0\tFAIL-INPROG: 0\tWARN-NEW: 1",
            "2026-10-07 09:40:52,198 I/O error: [Errno 5] ZAP failed to access: http://127.0.0.1:1",
        ):
            self.assertFalse(is_noisy_zap_line(line), line)


class ScanFindingsTests(unittest.TestCase):
    def scan_folder(self, static_findings=(), routes=()):
        folder = Path(self._tmp.name) / ("scan-" + str(id(static_findings)) + str(id(routes)))
        folder.mkdir()
        if static_findings:
            (folder / "static-findings.json").write_text(json.dumps({"findings": list(static_findings)}))
        if routes:
            (folder / "route-review.json").write_text(json.dumps({"routes": list(routes)}))
        return folder

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)

    def test_reads_static_findings_as_rule_path_line_tuples(self):
        folder = self.scan_folder(static_findings=[{"rule": "r1", "path": "a.ts", "line": 3}])
        static, routes = scan_findings(folder)
        self.assertEqual(static, {("r1", "a.ts", 3)})
        self.assertEqual(routes, set())

    def test_reads_routes_with_any_unauthenticated_handler(self):
        folder = self.scan_folder(routes=[
            {"path": "/api/open", "handlers": [{"authentication": False}]},
            {"path": "/api/mixed", "handlers": [{"authentication": True}, {"authentication": False}]},
            {"path": "/api/closed", "handlers": [{"authentication": True}]},
        ])
        _, routes = scan_findings(folder)
        self.assertEqual(routes, {"/api/open", "/api/mixed"})

    def test_missing_files_yield_empty_sets(self):
        folder = Path(self._tmp.name) / "empty-scan"
        folder.mkdir()
        self.assertEqual(scan_findings(folder), (set(), set()))


class CompareScansTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)

    def folder(self, name, static_findings=(), routes=()):
        path = Path(self._tmp.name) / name
        path.mkdir()
        (path / "static-findings.json").write_text(json.dumps({"findings": list(static_findings)}))
        (path / "route-review.json").write_text(json.dumps({"routes": list(routes)}))
        return path

    def test_new_and_resolved_findings_and_routes_are_both_reported(self):
        older = self.folder(
            "older",
            static_findings=[{"rule": "r1", "path": "a.ts", "line": 1}],
            routes=[{"path": "/api/old-gap", "handlers": [{"authentication": False}]}],
        )
        newer = self.folder(
            "newer",
            static_findings=[{"rule": "r2", "path": "b.ts", "line": 2}],
            routes=[{"path": "/api/new-gap", "handlers": [{"authentication": False}]}],
        )
        diff = compare_scans(older, newer)
        self.assertEqual(diff["new_static"], [("r2", "b.ts", 2)])
        self.assertEqual(diff["resolved_static"], [("r1", "a.ts", 1)])
        self.assertEqual(diff["new_no_auth_routes"], ["/api/new-gap"])
        self.assertEqual(diff["resolved_no_auth_routes"], ["/api/old-gap"])

    def test_identical_scans_report_no_differences(self):
        shared_static = [{"rule": "r1", "path": "a.ts", "line": 1}]
        shared_routes = [{"path": "/api/gap", "handlers": [{"authentication": False}]}]
        older = self.folder("older", static_findings=shared_static, routes=shared_routes)
        newer = self.folder("newer", static_findings=shared_static, routes=shared_routes)
        diff = compare_scans(older, newer)
        self.assertFalse(any(diff.values()))


class MissingLocalAttackImagesTests(unittest.TestCase):
    def test_images_missing_when_docker_inspect_fails(self):
        with unittest.mock.patch("subprocess.run") as run:
            run.return_value = MagicMock(returncode=1)
            self.assertEqual(set(missing_local_attack_images()),
                              {"projectdiscovery/nuclei:latest", "ghcr.io/zaproxy/zaproxy:stable"})

    def test_no_images_missing_when_docker_inspect_succeeds(self):
        with unittest.mock.patch("subprocess.run") as run:
            run.return_value = MagicMock(returncode=0)
            self.assertEqual(missing_local_attack_images(), [])
