import subprocess
import tempfile
import unittest
from pathlib import Path

from vaptkit.process import git


class GitEncodingTests(unittest.TestCase):
    """git() must never crash on repo content outside the OS's default codepage.

    On Windows, subprocess text mode defaults to the system codepage (cp1252) with
    strict decoding; a scanned repo's source files are not guaranteed to be cp1252 or
    even valid UTF-8, so git() must decode with errors="replace" instead of failing.
    """

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.repo = Path(self.directory.name)
        subprocess.run(["git", "init", "--quiet", str(self.repo)], check=True)
        subprocess.run(["git", "-C", str(self.repo), "config", "user.email", "a@b.c"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "config", "user.name", "a"], check=True)

    def commit_bytes(self, name: str, content: bytes) -> str:
        (self.repo / name).write_bytes(content)
        subprocess.run(["git", "-C", str(self.repo), "add", name], check=True)
        subprocess.run(["git", "-C", str(self.repo), "commit", "--quiet", "-m", "add"], check=True)
        return git(self.repo, "rev-parse", "HEAD")

    def test_non_utf8_file_content_does_not_raise(self):
        sha = self.commit_bytes("weird.txt", b"before \x8f after")
        self.assertIn("before", git(self.repo, "show", f"{sha}:weird.txt"))

    def test_normal_utf8_content_is_read_correctly(self):
        sha = self.commit_bytes("hello.txt", "café 🚀".encode())
        self.assertEqual(git(self.repo, "show", f"{sha}:hello.txt"), "café 🚀")


if __name__ == "__main__":
    unittest.main()
