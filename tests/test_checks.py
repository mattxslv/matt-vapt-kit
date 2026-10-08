import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vaptkit.checks import audit_commit, check, checked_revision, lockfiles, pushed_updates, severity_band, summarize_osv
from vaptkit.hooks import Findings, install, protect, uninstall
from vaptkit.process import ToolError, git


class PushTests(unittest.TestCase):
    def test_ref_selection_deletions_tags_and_multiple_tips(self):
        one, two, zero = "1" * 40, "2" * 40, "0" * 40
        lines = f"refs/heads/main {one} refs/heads/main {two}\n"
        lines += f"refs/tags/v1 {one} refs/tags/v1 {zero}\n"
        lines += f"(delete) {zero} refs/heads/old {one}\n"
        lines += f"refs/heads/new {one} refs/heads/new {zero}\n"
        self.assertEqual(pushed_updates(lines), [(one, None), (one, two)])
        with self.assertRaises(ToolError):
            pushed_updates("untrusted garbage")

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

    def test_no_lockfile_means_no_audit(self):
        real_run = subprocess.run
        docker_calls = []

        def process(command, **kwargs):
            if command[0] == "docker":
                docker_calls.append(command)
            return real_run(command, **kwargs)

        with patch("vaptkit.checks.subprocess.run", side_effect=process):
            self.assertIsNone(audit_commit(self.repo, git(self.repo, "rev-parse", "HEAD")))
        self.assertEqual(docker_calls, [])

    def test_static_scanner_can_read_private_export_without_root_capabilities(self):
        def process(command, **kwargs):
            if command[-1] == "/src":
                self.assertIn("--user", command)
                self.assertIn(f"{os.getuid()}:{os.getgid()}", command)
                self.assertIn("HOME=/tmp", command)
                mounts = [command[index + 1] for index, value in enumerate(command) if value == "-v"]
                source = next(mount.split(":/src:ro")[0] for mount in mounts if mount.endswith(":/src:ro"))
                self.assertTrue((Path(source) / "file.txt").is_file())
                self.assertEqual(Path(source).stat().st_mode & 0o777, 0o700)

        with patch("vaptkit.checks.run", side_effect=process):
            check(self.repo, "HEAD", static=True)

    def test_windows_docker_commands_use_linux_paths_and_no_host_uid(self):
        commands = []

        def process(command, **kwargs):
            commands.append(command)
            if command[:2] == ["git", "clone"]:
                subprocess.run(command, check=True)

        with patch("vaptkit.checks.WINDOWS", True), patch("vaptkit.checks.run", side_effect=process), \
                patch("os.getuid", side_effect=AttributeError("Windows has no getuid")):
            check(self.repo, "HEAD", static=True)
        clone = next(command for command in commands if command[:2] == ["git", "clone"])
        self.assertNotIn("--shared", clone)
        for command in (command for command in commands if command[0] == "docker"):
            self.assertNotIn("--user", command)
            mounts = [command[index + 1] for index, value in enumerate(command) if value == "-v"]
            self.assertTrue(all(mount.split(":")[-2].startswith("/") for mount in mounts), mounts)
        history = next(command for command in commands if command[0] == "docker" and "git" in command)
        self.assertIn("/scan/history.git", history)
        self.assertIn("GIT_CONFIG_VALUE_0=*", history)
        self.assertNotIn(str(self.repo), " ".join(history))

    def test_audit_uses_pushed_lockfile_not_working_tree(self):
        (self.repo / "composer.lock").write_text('{"packages": ["committed"]}')
        git(self.repo, "add", "composer.lock")
        git(self.repo, "commit", "-qm", "Add lockfile")
        (self.repo / "composer.lock").write_text('{"packages": ["dirty"]}')
        real_run = subprocess.run
        seen = {}

        def process(command, **kwargs):
            if command[0] != "docker":
                return real_run(command, **kwargs)
            mount = next(arg for arg in command if arg.endswith(":/src:ro")).rsplit(":/src:ro", 1)[0]
            seen["lockfile"] = (Path(mount) / "composer.lock").read_text()
            seen["command"] = command
            return subprocess.CompletedProcess(command, 1, stdout=json.dumps({"results": [{"packages": [{
                "package": {"name": "guzzlehttp/guzzle", "version": "7.4.0", "ecosystem": "Packagist"},
                "groups": [{"ids": ["GHSA-1"], "max_severity": "8.0"}, {"ids": ["GHSA-2"], "max_severity": "5.3"}],
            }]}]}), stderr="")

        with patch("vaptkit.checks.subprocess.run", side_effect=process):
            report = audit_commit(self.repo, git(self.repo, "rev-parse", "HEAD"))
        self.assertEqual(seen["lockfile"], '{"packages": ["committed"]}')
        self.assertNotIn("--network=none", seen["command"])
        self.assertEqual(report["vulnerabilities"], 2)
        self.assertEqual(report["severity"]["high"], 1)
        self.assertEqual(report["severity"]["medium"], 1)
        self.assertEqual(report["lockfiles"], ["composer.lock"])

    def test_scanner_finding_no_packages_counts_as_no_audit(self):
        (self.repo / "package-lock.json").write_text("{}")
        git(self.repo, "add", "package-lock.json")
        git(self.repo, "commit", "-qm", "Add empty lockfile")
        real_run = subprocess.run
        with patch("vaptkit.checks.subprocess.run", side_effect=lambda command, **kwargs: (
            subprocess.CompletedProcess(command, 128, stdout="", stderr="") if command[0] == "docker"
            else real_run(command, **kwargs)
        )):
            self.assertIsNone(audit_commit(self.repo, git(self.repo, "rev-parse", "HEAD")))


class DependencyReportTests(unittest.TestCase):
    def test_lockfiles_found_anywhere_except_vendored_folders(self):
        listing = ["package.json", "pnpm-lock.yaml", "api/composer.lock", "vendor/x/composer.lock",
                   "node_modules/a/package-lock.json", "README.md"]
        self.assertEqual(lockfiles(listing), ["pnpm-lock.yaml", "api/composer.lock"])

    def test_severity_bands_follow_cvss(self):
        self.assertEqual([severity_band(score) for score in ("9.8", "7.0", "5.3", "2.1", "", None)],
                         ["critical", "high", "medium", "low", "unknown", "unknown"])

    def test_summary_counts_each_advisory_group_once_worst_first(self):
        summary = summarize_osv({"results": [{"packages": [
            {"package": {"name": "a", "version": "1"}, "groups": [{"ids": ["X"], "max_severity": "4.0"}]},
            {"package": {"name": "b", "version": "2"}, "groups": [{"ids": ["Y"], "max_severity": "9.1"}]},
        ]}]})
        self.assertEqual(summary["vulnerabilities"], 2)
        self.assertEqual(summary["packages"], 2)
        self.assertEqual(summary["top"][0]["package"], "b")


class HookProtectTests(unittest.TestCase):
    def test_dependency_audit_still_runs_when_the_secret_scan_cannot_start(self):
        def fake_git(repo, *args):
            return "1" if args[0] == "rev-list" else "package.json\nsrc/app.ts"

        with patch("vaptkit.hooks.push_revisions", return_value="a..b"), \
                patch("vaptkit.hooks.git", side_effect=fake_git), \
                patch("vaptkit.hooks.scan_history", side_effect=FileNotFoundError("docker")), \
                patch("vaptkit.hooks.audit_commit", return_value={
                    "severity": {"critical": 0, "high": 1, "medium": 0, "low": 0, "unknown": 0},
                    "top": [{"package": "lodash", "version": "4.17.20"}]}) as audit:
            with self.assertRaises(Findings):
                protect(Path("."), "b" * 40, "a" * 40)
        audit.assert_called_once()


    def test_composer_lockfile_changes_also_trigger_the_audit(self):
        def fake_git(repo, *args):
            return "1" if args[0] == "rev-list" else "backend/composer.lock"

        with patch("vaptkit.hooks.push_revisions", return_value="a..b"), \
                patch("vaptkit.hooks.git", side_effect=fake_git), \
                patch("vaptkit.hooks.scan_history", return_value=None), \
                patch("vaptkit.hooks.audit_commit", return_value=None) as audit:
            protect(Path("."), "b" * 40, "a" * 40)
        audit.assert_called_once()
