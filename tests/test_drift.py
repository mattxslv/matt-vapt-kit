import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from vaptkit.drift import build_drift, render_markdown
from vaptkit.process import git


class DriftTests(unittest.TestCase):
    def test_finding_fixed_on_one_branch_points_at_the_fixing_commit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True)
            for args in (["config", "user.email", "t@example.invalid"], ["config", "user.name", "T"]):
                git(repo, *args)
            (repo / "app").mkdir()
            (repo / "app/profile.ts").write_text("export const v = 1\n")
            git(repo, "add", ".")
            git(repo, "commit", "-qm", "Initial app")
            main_sha = git(repo, "rev-parse", "HEAD")
            git(repo, "checkout", "-qb", "staging")
            (repo / "app/profile.ts").write_text("export const v = 2 // take user id from session\n")
            git(repo, "commit", "-qam", "Fix profile ownership check")
            staging_sha = git(repo, "rev-parse", "HEAD")

            def scan_folder(name, sha, with_bug):
                folder = root / name
                folder.mkdir()
                (folder / "summary.json").write_text(json.dumps({"revision": sha}))
                findings = [{"title": "Handler changes a record chosen by a user ID from the request",
                             "path": "/api/profile", "impact": "PUT handler in app/profile.ts. Detail"}] if with_bug else []
                (folder / "route-review.json").write_text(json.dumps({"findings": findings}))
                return folder

            drift = build_drift(repo, [("main", scan_folder("m", main_sha, True)),
                                       ("staging", scan_folder("s", staging_sha, False))])
        open_on_main = drift["open_only_on"]["main"]
        self.assertEqual(len(open_on_main), 1)
        self.assertEqual(open_on_main[0]["kind"], "Access control")
        self.assertIn("Fix profile ownership check", open_on_main[0]["fix_commits"][0])
        self.assertEqual(drift["open_only_on"]["staging"], [])
        self.assertTrue(any("ownership" in commit for commit in drift["security_commits_only_on"]["staging"]))
        self.assertIn("Open on main, not on staging (1)", render_markdown(drift, "demo"))
