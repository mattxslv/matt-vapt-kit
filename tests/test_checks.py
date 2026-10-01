import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vaptkit.checks import audit_commit, checked_revision, pushed_commits
from vaptkit.hooks import install, uninstall
from vaptkit.process import ToolError, git


class PushTests(unittest.TestCase):
    def test_ref_selection_deletions_tags_and_multiple_tips(self):
        one, two, zero = "1" * 40, "2" * 40, "0" * 40
        lines = f"refs/heads/main {one} refs/heads/main {two}\n"
        lines += f"refs/tags/v1 {one} refs/tags/v1 {zero}\n"
        lines += f"(delete) {zero} refs/heads/old {one}\n"
        self.assertEqual(pushed_commits(lines), [one])
        with self.assertRaises(ToolError):
            pushed_commits("untrusted garbage")

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.repo = Path(self.directory.name) / "repo"
        self.repo.mkdir()
        git(self.repo, "init", "-q")
        git(self.repo, "config", "user.name", "Test")
        git(self.repo, "config", "user.email", "test@example.invalid")
        git(self.repo, "config", "core.hooksPath", str(self.repo / "previous"))
        (self.repo / "file.txt").write_text("fixture\n")
        git(self.repo, "add", ".")
        git(self.repo, "commit", "-qm", "Add fixture")

    def test_exact_commit_resolution(self):
        self.assertEqual(checked_revision(self.repo, "HEAD"), git(self.repo, "rev-parse", "HEAD"))
        with self.assertRaises(ToolError):
            checked_revision(self.repo, "--all")

    def test_preserve_previous_hooks_and_restore(self):
        previous = self.repo / "previous"
        previous.mkdir()
        hook = previous / "commit-msg"
        hook.write_text("#!/bin/sh\nexit 0\n")
        hook.chmod(0o700)
        install(self.repo)
        current = Path(git(self.repo, "config", "--get", "core.hooksPath"))
        self.assertEqual((current / "commit-msg").resolve(), hook)
        with self.assertRaises(ToolError):
            install(self.repo)
        uninstall(self.repo)
        self.assertEqual(git(self.repo, "config", "--get", "core.hooksPath"), str(previous))
        self.assertTrue(hook.exists())

    def test_existing_hook_failure_and_stdin_preserved(self):
        previous = self.repo / "previous"
        previous.mkdir()
        hook = previous / "pre-push"
        hook.write_text("#!/bin/sh\ncat > received.txt\nexit 9\n")
        hook.chmod(0o700)
        install(self.repo)
        current = Path(git(self.repo, "config", "--get", "core.hooksPath"))
        result = subprocess.run(
            [str(current / "pre-push"), "origin", "test"], input="original input\n",
            text=True, capture_output=True, cwd=self.repo,
        )
        self.assertEqual(result.returncode, 1)
        self.assertEqual((self.repo / "received.txt").read_text(), "original input\n")
        self.assertIn("Existing pre-push hook failed", result.stderr)

    def test_non_node_audit_explicit(self):
        with patch("vaptkit.checks.run") as run:
            audit_commit(self.repo, git(self.repo, "rev-parse", "HEAD"))
            run.assert_not_called()

    def test_audit_uses_pushed_lockfile_not_working_tree(self):
        (self.repo / "package.json").write_text(json.dumps({"packageManager": "pnpm@10.27.0"}))
        (self.repo / "pnpm-lock.yaml").write_text("committed lockfile\n")
        git(self.repo, "add", "package.json", "pnpm-lock.yaml")
        git(self.repo, "commit", "-qm", "Add manifests")
        (self.repo / "pnpm-lock.yaml").write_text("dirty lockfile\n")
        real_run = subprocess.run

        def process(command, **kwargs):
            if command[:2] == ["pnpm", "--version"]:
                return subprocess.CompletedProcess(command, 0, stdout="10.27.0\n")
            return real_run(command, **kwargs)

        def audit(command, *, cwd):
            self.assertEqual((cwd / "pnpm-lock.yaml").read_text(), "committed lockfile\n")
            self.assertIn("--audit-level=high", command)

        with patch("vaptkit.checks.subprocess.run", side_effect=process), patch(
            "vaptkit.checks.run", side_effect=audit
        ):
            audit_commit(self.repo, git(self.repo, "rev-parse", "HEAD"))
