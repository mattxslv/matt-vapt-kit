import tempfile
import unittest
from pathlib import Path

from vaptkit.native_scan import fixed_port_templates


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


if __name__ == "__main__":
    unittest.main()
