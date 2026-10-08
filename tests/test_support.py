import getpass
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from vaptkit.support import URL_LIMIT, diagnostics, issue_url, last_error_file, record_error, sanitize


class SanitizeTests(unittest.TestCase):
    def test_home_folder_and_username_are_hidden(self):
        with patch("vaptkit.support.getpass.getuser", return_value="jdelacruz"), \
                patch("vaptkit.support.Path.home", return_value=Path("/home/jdelacruz")):
            text = sanitize("Error in /home/jdelacruz/HRMIS/app.cs for jdelacruz")
        self.assertEqual(text, "Error in ~/HRMIS/app.cs for <user>")


class IssueUrlTests(unittest.TestCase):
    def test_link_is_prefilled_and_kept_under_the_browser_limit(self):
        url = issue_url("owner/repo", "Pilot problem: scan failed", "x" * 20000)
        self.assertLessEqual(len(url), URL_LIMIT + 300)
        query = parse_qs(urlsplit(url).query)
        self.assertTrue(url.startswith("https://github.com/owner/repo/issues/new?"))
        self.assertEqual(query["title"], ["Pilot problem: scan failed"])
        self.assertIn("Shortened to fit", query["body"][0])

    def test_short_reports_are_sent_whole(self):
        query = parse_qs(urlsplit(issue_url("owner/repo", "t", "## Environment\n- Kit: v1")).query)
        self.assertEqual(query["body"], ["## Environment\n- Kit: v1"])


class LastErrorTests(unittest.TestCase):
    def test_recorded_error_appears_in_diagnostics_without_the_home_path(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"XDG_STATE_HOME": directory}):
            record_error("scan", f"Cannot read {Path.home()}/Projects/hrmis")
            self.assertTrue(last_error_file().is_file())
            report = diagnostics([("git", True, "Executable available.")], 2)
        self.assertIn("· scan", report)
        self.assertIn("~/Projects/hrmis", report)
        self.assertNotIn(str(Path.home()), report)
        self.assertIn("OK git", report)
