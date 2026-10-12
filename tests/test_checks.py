import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vaptkit.checks import (audit_commit, check, checked_revision, dependency_scopes, history_findings, lockfiles, pnpm_runtime,
                            pushed_updates, severity_band, summarize_osv)
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
        real_run = subprocess.run

        def process(command, *args, **kwargs):
            if command[0] != "docker":
                return real_run(command, *args, **kwargs)
            if "gitleaks" in str(command):
                count = git(self.repo, "rev-list", "--count", "HEAD")
                return subprocess.CompletedProcess(command, 0, stdout="[]", stderr=f"{count} commits scanned.")
            if command[-1] == "/src":
                self.assertIn("--user", command)
                self.assertIn(f"{os.getuid()}:{os.getgid()}", command)
                self.assertIn("HOME=/tmp", command)
                mounts = [command[index + 1] for index, value in enumerate(command) if value == "-v"]
                source = next(mount.split(":/src:ro")[0] for mount in mounts if mount.endswith(":/src:ro"))
                self.assertTrue((Path(source) / "file.txt").is_file())
                self.assertEqual(Path(source).stat().st_mode & 0o777, 0o700)
            return real_run(command, *args, **kwargs)

        with patch("vaptkit.checks.run", side_effect=process), \
                patch("vaptkit.checks.subprocess.run", side_effect=process):
            check(self.repo, "HEAD", static=True)

    def test_windows_docker_commands_use_linux_paths_and_no_host_uid(self):
        commands = []
        real_run = subprocess.run

        def process(command, *args, **kwargs):
            commands.append(command)
            if command[0] != "docker":
                return real_run(command, *args, **kwargs)
            if "gitleaks" in str(command):
                count = git(self.repo, "rev-list", "--count", "HEAD")
                return subprocess.CompletedProcess(command, 0, stdout="[]", stderr=f"{count} commits scanned.")
            return real_run(command, *args, **kwargs)

        with patch("vaptkit.checks.WINDOWS", True), patch("vaptkit.checks.run", side_effect=process), \
                patch("vaptkit.checks.subprocess.run", side_effect=process), \
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

    def test_committed_osv_scanner_toml_is_passed_as_config(self):
        (self.repo / "composer.lock").write_text('{"packages": ["committed"]}')
        (self.repo / "osv-scanner.toml").write_text('[[IgnoredVulns]]\nid = "GHSA-1"\nreason = "waived"\n')
        git(self.repo, "add", "composer.lock", "osv-scanner.toml")
        git(self.repo, "commit", "-qm", "Add lockfile and waiver")
        real_run = subprocess.run
        seen = {}

        def process(command, **kwargs):
            if command[0] != "docker":
                return real_run(command, **kwargs)
            mount = next(arg for arg in command if arg.endswith(":/src:ro")).rsplit(":/src:ro", 1)[0]
            seen["waiver"] = (Path(mount) / "osv-scanner.toml").read_text()
            seen["command"] = command
            return subprocess.CompletedProcess(command, 0, stdout=json.dumps({"results": []}), stderr="")

        with patch("vaptkit.checks.subprocess.run", side_effect=process):
            audit_commit(self.repo, git(self.repo, "rev-parse", "HEAD"))
        self.assertIn('id = "GHSA-1"', seen["waiver"])
        self.assertIn("--config", seen["command"])
        self.assertEqual(seen["command"][seen["command"].index("--config") + 1], "/src/osv-scanner.toml")

    def test_no_osv_scanner_toml_omits_config_flag(self):
        (self.repo / "composer.lock").write_text('{"packages": ["committed"]}')
        git(self.repo, "add", "composer.lock")
        git(self.repo, "commit", "-qm", "Add lockfile")
        real_run = subprocess.run
        seen = {}

        def process(command, **kwargs):
            if command[0] != "docker":
                return real_run(command, **kwargs)
            seen["command"] = command
            return subprocess.CompletedProcess(command, 0, stdout=json.dumps({"results": []}), stderr="")

        with patch("vaptkit.checks.subprocess.run", side_effect=process):
            audit_commit(self.repo, git(self.repo, "rev-parse", "HEAD"))
        self.assertNotIn("--config", seen["command"])

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
                   "node_modules/a/package-lock.json", "README.md", "Hrmis.Web/Hrmis.Web.csproj",
                   "Intranet/packages.config", "Hrmis.Web/Program.cs"]
        self.assertEqual(lockfiles(listing), ["pnpm-lock.yaml", "api/composer.lock", "Hrmis.Web/Hrmis.Web.csproj",
                                              "Intranet/packages.config"])

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
                    "runtime_severity": {"critical": 0, "high": 1, "medium": 0, "low": 0, "unknown": 0},
                    "top": [{"package": "lodash", "version": "4.17.20", "scope": "runtime"}]}) as audit:
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


class DependencyScopeTests(unittest.TestCase):
    def test_pnpm_runtime_follows_only_runtime_dependencies(self):
        lock = {"importers": {".": {"dependencies": {"next": {"specifier": "^15", "version": "15.5.4(react@19.0.0)"}},
                                    "devDependencies": {"handlebars": {"specifier": "^4", "version": "4.7.8"}}}},
                "snapshots": {"next@15.5.4(react@19.0.0)": {"dependencies": {"postcss": "8.4.31"}},
                              "postcss@8.4.31": {}, "handlebars@4.7.8": {"dependencies": {"minimist": "1.2.8"}},
                              "minimist@1.2.8": {}}}
        self.assertEqual(pnpm_runtime(lock), {("next", "15.5.4"), ("postcss", "8.4.31")})

    def test_scopes_for_npm_composer_and_pnpm_lockfiles(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "package-lock.json").write_text(json.dumps({"packages": {
                "": {}, "node_modules/express": {"version": "4.17.1"},
                "node_modules/jest/node_modules/braces": {"version": "3.0.2", "dev": True}}}))
            (root / "composer.lock").write_text(json.dumps({"packages": [{"name": "guzzle"}],
                                                            "packages-dev": [{"name": "phpunit"}]}))
            npm, composer = dependency_scopes(root, "package-lock.json"), dependency_scopes(root, "composer.lock")
            self.assertEqual(npm("express", "4.17.1"), "runtime")
            self.assertEqual(npm("braces", "3.0.2"), "dev")
            self.assertEqual(npm("left-pad", "1.0.0"), "unknown")
            self.assertEqual(composer("phpunit", "9"), "dev")
            self.assertEqual(composer("guzzle", "7"), "runtime")

    def test_dev_only_vulnerabilities_do_not_count_as_runtime(self):
        summary = summarize_osv({"results": [{"source": {"path": "/src/pnpm-lock.yaml"}, "packages": [
            {"package": {"name": "handlebars", "version": "4.7.8"}, "groups": [{"ids": ["A"], "max_severity": "9.8"}]},
            {"package": {"name": "next", "version": "15.5.4"}, "groups": [{"ids": ["B"], "max_severity": "7.5"}]},
        ]}]}, {"pnpm-lock.yaml": lambda name, version: "dev" if name == "handlebars" else "runtime"})
        self.assertEqual(summary["severity"]["critical"], 1)
        self.assertEqual(summary["runtime_severity"]["critical"], 0)
        self.assertEqual(summary["runtime_severity"]["high"], 1)
        self.assertEqual(summary["top"][0]["package"], "next")


class HistoryFindingsTests(unittest.TestCase):
    def test_placeholders_are_marked_and_values_never_returned(self):
        report = json.dumps([
            {"RuleID": "curl-auth-header", "File": "docs/DEPLOY.md", "StartLine": 203, "Commit": "a" * 40,
             "Fingerprint": "a:docs/DEPLOY.md:curl-auth-header:203", "Secret": "REAL_LOOKING_9f8e7d6c"},  # gitleaks:allow (deliberate fake for tests)
            {"RuleID": "generic-api-key", "File": "lib/config.ts", "StartLine": 4, "Commit": "b" * 40,
             "Fingerprint": "b:lib/config.ts:generic-api-key:4", "Secret": "YOUR_API_KEY_HERE"},  # gitleaks:allow (deliberate fake for tests)
            {"RuleID": "generic-api-key", "File": "lib/client.ts", "StartLine": 9, "Commit": "c" * 40,
             "Fingerprint": "c:lib/client.ts:generic-api-key:9", "Secret": "k9Q2vX7pL4mN8rT1"},  # gitleaks:allow (deliberate fake for tests)
        ])
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            git(repo, "init", "-q")
            git(repo, "config", "user.email", "t@example.invalid")
            git(repo, "config", "user.name", "T")
            (repo / "a.txt").write_text("x")
            git(repo, "add", ".")
            git(repo, "commit", "-qm", "init")
            real_run = subprocess.run

            def process(command, **kwargs):
                if command[0] == "docker":
                    self.assertIn("-", command)
                    self.assertNotIn("--redact", command)
                    count = git(repo, "rev-list", "--count", "HEAD")
                    return subprocess.CompletedProcess(command, 1, stdout=report, stderr=f"{count} commits scanned.")
                return real_run(command, **kwargs)

            with patch("vaptkit.checks.subprocess.run", side_effect=process), patch("vaptkit.checks.run", side_effect=lambda c, **k: real_run(c, check=True)):
                found = history_findings(repo, git(repo, "rev-parse", "HEAD"))
        self.assertEqual([item["placeholder"] for item in found], [True, True, False])
        self.assertEqual(found[2]["commit"], "c" * 12)
        self.assertNotIn("k9Q2vX7pL4mN8rT1", json.dumps(found))
        self.assertTrue(all("Secret" not in item and "secret" not in item for item in found))

    def test_undercounted_commit_scan_is_rejected_not_reported_as_clean(self):
        # Reproduces a real gitleaks bug found against an actual 1483-commit repository: it
        # silently stopped at 1232 commits scanned, no error or warning, missing 74 real secrets
        # that only existed in the unwalked tail of history. A scan that covered fewer commits
        # than the branch actually has must never be reported as "no leaks found".
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            git(repo, "init", "-q")
            git(repo, "config", "user.email", "t@example.invalid")
            git(repo, "config", "user.name", "T")
            for message in ("first", "second", "third"):
                (repo / "a.txt").write_text(message)
                git(repo, "add", ".")
                git(repo, "commit", "-qm", message)
            real_run = subprocess.run

            def process(command, **kwargs):
                if command[0] == "docker":
                    return subprocess.CompletedProcess(command, 0, stdout="[]", stderr="2 commits scanned.")
                return real_run(command, **kwargs)

            with patch("vaptkit.checks.subprocess.run", side_effect=process), \
                    patch("vaptkit.checks.run", side_effect=lambda c, **k: real_run(c, check=True)):
                with self.assertRaises(ToolError):
                    history_findings(repo, git(repo, "rev-parse", "HEAD"))

    def test_missing_commits_scanned_line_is_also_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            git(repo, "init", "-q")
            git(repo, "config", "user.email", "t@example.invalid")
            git(repo, "config", "user.name", "T")
            (repo / "a.txt").write_text("x")
            git(repo, "add", ".")
            git(repo, "commit", "-qm", "init")
            real_run = subprocess.run

            def process(command, **kwargs):
                if command[0] == "docker":
                    return subprocess.CompletedProcess(command, 0, stdout="[]", stderr="")
                return real_run(command, **kwargs)

            with patch("vaptkit.checks.subprocess.run", side_effect=process), \
                    patch("vaptkit.checks.run", side_effect=lambda c, **k: real_run(c, check=True)):
                with self.assertRaises(ToolError):
                    history_findings(repo, git(repo, "rev-parse", "HEAD"))


class RouteReviewInCheckTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.repo = Path(self.directory.name) / "repo"
        self.repo.mkdir()
        git(self.repo, "init", "-q")
        git(self.repo, "config", "user.name", "Fixture")
        git(self.repo, "config", "user.email", "fixture@example.invalid")

    def commit(self, route_body: str):
        (self.repo / "app/api/evaluator/profile").mkdir(parents=True, exist_ok=True)
        (self.repo / "app/api/evaluator/profile/route.ts").write_text(route_body)
        git(self.repo, "add", ".")
        git(self.repo, "commit", "-qm", "route")
        return git(self.repo, "rev-parse", "HEAD")

    def run_check(self, project_dir: Path):
        with patch("vaptkit.checks.history_findings", return_value=[]), \
                patch("vaptkit.checks.audit_commit", return_value=None), \
                patch("vaptkit.checks.PROJECTS_DIR", project_dir):
            check(self.repo, "HEAD")

    def test_no_matching_project_config_is_not_applicable(self):
        self.commit("export async function GET() { return Response.json({}) }")
        with tempfile.TemporaryDirectory() as empty_projects:
            with patch("vaptkit.checks.history_findings", return_value=[]), \
                    patch("vaptkit.checks.audit_commit", return_value=None), \
                    patch("vaptkit.checks.PROJECTS_DIR", Path(empty_projects)):
                check(self.repo, "HEAD", routes=True)  # must not raise

    def test_unauthenticated_handler_fails_the_check(self):
        self.commit("export async function PUT(req) { return Response.json(await save(req)) }")
        with tempfile.TemporaryDirectory() as projects_dir:
            config = Path(projects_dir) / "repo.vapt.yml"
            config.write_text("schema_version: 1\nproject: repo\n"
            "target:\n  environment: staging\n  url: https://staging.example.invalid\n"
            "  allowed_hosts: [staging.example.invalid]\n  verification: pending\n"
            "scope:\n  api_prefixes: [/api/]\n  excluded_prefixes: []\n  roles: []\n"
            "credentials: {}\nreview: {}\n")
            with patch("vaptkit.checks.history_findings", return_value=[]), \
                    patch("vaptkit.checks.audit_commit", return_value=None), \
                    patch("vaptkit.checks.PROJECTS_DIR", Path(projects_dir)):
                with self.assertRaises(ToolError):
                    check(self.repo, "HEAD", routes=True)

    def test_protected_handler_passes(self):
        self.commit("export async function PUT(req) { "
                    "const session = await requireAuth(req); return Response.json(await save(req)) }")
        with tempfile.TemporaryDirectory() as projects_dir:
            config = Path(projects_dir) / "repo.vapt.yml"
            config.write_text("schema_version: 1\nproject: repo\n"
            "target:\n  environment: staging\n  url: https://staging.example.invalid\n"
            "  allowed_hosts: [staging.example.invalid]\n  verification: pending\n"
            "scope:\n  api_prefixes: [/api/]\n  excluded_prefixes: []\n  roles: []\n"
            "credentials: {}\nreview: {}\n")
            with patch("vaptkit.checks.history_findings", return_value=[]), \
                    patch("vaptkit.checks.audit_commit", return_value=None), \
                    patch("vaptkit.checks.PROJECTS_DIR", Path(projects_dir)):
                check(self.repo, "HEAD", routes=True)  # must not raise

    def test_routes_false_skips_the_review_even_with_a_bug_present(self):
        self.commit("export async function PUT(req) { return Response.json(await save(req)) }")
        with tempfile.TemporaryDirectory() as projects_dir:
            (Path(projects_dir) / "repo.vapt.yml").write_text("schema_version: 1\nproject: repo\n"
            "target:\n  environment: staging\n  url: https://staging.example.invalid\n"
            "  allowed_hosts: [staging.example.invalid]\n  verification: pending\n"
            "scope:\n  api_prefixes: [/api/]\n  excluded_prefixes: []\n  roles: []\n"
            "credentials: {}\nreview: {}\n")
            with patch("vaptkit.checks.history_findings", return_value=[]), \
                    patch("vaptkit.checks.audit_commit", return_value=None), \
                    patch("vaptkit.checks.PROJECTS_DIR", Path(projects_dir)):
                check(self.repo, "HEAD", routes=False)  # must not raise: review not requested
