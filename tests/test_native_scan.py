import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vaptkit.native_scan import _which_on_path, fixed_port_templates


class FixedPortTemplatesTests(unittest.TestCase):
    def test_missing_directory_returns_empty(self):
        self.assertEqual(fixed_port_templates(Path("/no/such/dir")), [])

    def test_flags_templates_that_hardcode_their_own_port(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "safe.yaml").write_text("http:\n  - raw: 'GET {{BaseURL}}/'\n")
            (root / "fixed.yaml").write_text("http:\n  - raw: 'GET {{BaseURL}}:4040/'\n")
            nested = root / "nested"
            nested.mkdir()
            (nested / "also-fixed.yaml").write_text("http:\n  - raw: 'GET {{Host}}:8080/'\n")
            found = fixed_port_templates(root)
            self.assertEqual(sorted(Path(path).name for path in found), ["also-fixed.yaml", "fixed.yaml"])


class WhichOnPathTests(unittest.TestCase):
    def test_ignores_a_binary_planted_in_the_current_directory(self):
        """A malicious nuclei/zap in a scanned repo's working directory must not be picked up
        over the real PATH-installed tool - this is the Windows shutil.which() cwd-prepend risk."""
        with tempfile.TemporaryDirectory() as directory:
            fake = Path(directory) / "totally-fake-tool"
            fake.write_text("#!/bin/sh\necho fake\n")
            fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
            with patch.dict(os.environ, {"PATH": ""}), patch("os.getcwd", return_value=directory):
                self.assertIsNone(_which_on_path("totally-fake-tool"))

    def test_ignores_cwd_even_if_path_itself_is_poisoned_with_it(self):
        with tempfile.TemporaryDirectory() as directory:
            fake = Path(directory) / "totally-fake-tool"
            fake.write_text("#!/bin/sh\necho fake\n")
            fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
            with patch.dict(os.environ, {"PATH": directory}), patch("os.getcwd", return_value=directory):
                self.assertIsNone(_which_on_path("totally-fake-tool"))

    def test_finds_a_real_path_entry(self):
        with tempfile.TemporaryDirectory() as directory:
            real = Path(directory) / "totally-real-tool"
            real.write_text("#!/bin/sh\necho real\n")
            real.chmod(real.stat().st_mode | stat.S_IEXEC)
            with patch.dict(os.environ, {"PATH": directory}):
                self.assertEqual(_which_on_path("totally-real-tool"), str(real))


if __name__ == "__main__":
    unittest.main()
