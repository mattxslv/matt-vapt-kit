import unittest
from unittest.mock import MagicMock

from vaptkit.process import ToolError, stream
from vaptkit.menu import is_local_target, local_url, retry_input, staging_config, staging_recap


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
    def test_stream_returns_combined_output_and_exit_code(self):
        lines = []
        text, code = stream(["sh", "-c", "echo one; echo two"], lines.append)
        self.assertEqual(code, 0)
        self.assertEqual(lines, ["one", "two"])
        self.assertEqual(text, "one\ntwo")

    def test_stream_raises_if_command_cannot_start(self):
        with self.assertRaises(ToolError):
            stream(["definitely-not-a-real-executable"], lambda line: None)
