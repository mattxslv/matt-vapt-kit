import json
import os
import shlex
import subprocess
import sys
from pathlib import Path

from .checks import WINDOWS, audit_commit, pushed_updates, scan_history
from .process import ToolError, git, run

MARKER = "# matt-vapt-kit managed hook"
LEAK_EXIT_CODE = 42
DEPENDENCY_FILES = {"package.json", "pnpm-lock.yaml"}


class Findings(ToolError):
    """The check ran and found something; the push must be blocked."""


def _config(repo: Path, local=False):
    result = subprocess.run(
        ["git", "-C", str(repo), "config", *(["--local"] if local else []),
         "--get", "core.hooksPath"], capture_output=True, text=True,
    )
    if result.returncode not in (0, 1):
        raise ToolError("Cannot read Git hook configuration.")
    return result.stdout.strip() if result.returncode == 0 else None


def install(repo: Path) -> None:
    repo = Path(git(repo, "rev-parse", "--show-toplevel")).resolve()
    common = Path(git(repo, "rev-parse", "--path-format=absolute", "--git-common-dir"))
    destination = common / "matt-vapt-hooks"
    if destination.exists():
        raise ToolError("Managed hooks already exist; uninstall them before reinstalling.")
    original = _config(repo)
    previous = Path(original).expanduser() if original else common / "hooks"
    if not previous.is_absolute():
        previous = repo / previous
    local = _config(repo, local=True)
    destination.mkdir(mode=0o700)
    state = {"previous": str(previous), "local": local, "repo": str(repo)}
    (destination / "state.json").write_text(json.dumps(state))
    for hook in previous.iterdir() if previous.is_dir() else []:
        if hook.name != "pre-push" and hook.is_file() and os.access(hook, os.X_OK):
            if WINDOWS:
                # Symlinks need admin rights or Developer Mode on Windows; chain through a script instead.
                (destination / hook.name).write_text(
                    "#!/bin/sh\n" + MARKER + "\nexec sh " + shlex.quote(hook.resolve().as_posix()) + ' "$@"\n')
            else:
                (destination / hook.name).symlink_to(hook.resolve())
    wrapper = destination / "pre-push"
    wrapper.write_text(
        "#!/bin/sh\n" + MARKER + "\nexec "
        + shlex.quote(sys.executable) + " -m vaptkit.hooks "
        + shlex.quote(str(destination / "state.json")) + ' "$@"\n'
    )
    wrapper.chmod(0o700)
    git(repo, "config", "--local", "core.hooksPath", str(destination))
    print("Pre-push checks installed locally. Existing hooks are preserved; no files staged.")


def uninstall(repo: Path) -> None:
    repo = Path(git(repo, "rev-parse", "--show-toplevel")).resolve()
    common = Path(git(repo, "rev-parse", "--path-format=absolute", "--git-common-dir"))
    destination = common / "matt-vapt-hooks"
    if _config(repo) != str(destination):
        raise ToolError("Current hooks path is not managed by this toolkit; nothing changed.")
    state = json.loads((destination / "state.json").read_text())
    if MARKER not in (destination / "pre-push").read_text():
        raise ToolError("Managed wrapper was replaced; refusing to remove it.")
    allowed = {"pre-push", "state.json"}
    entries = list(destination.iterdir())
    if any(not entry.is_symlink() and entry.name not in allowed and MARKER not in entry.read_text(errors="replace")
           for entry in entries):
        raise ToolError("Unexpected files in hooks directory; refusing cleanup.")
    if state["local"] is None:
        git(repo, "config", "--local", "--unset", "core.hooksPath")
    else:
        git(repo, "config", "--local", "core.hooksPath", state["local"])
    for entry in entries:
        entry.unlink()
    destination.rmdir()
    print("Previous Git hook configuration restored.")


def push_revisions(repo: Path, local: str, remote: str | None) -> str:
    """git log arguments selecting only the commits this push adds to the remote."""
    known = remote is not None and subprocess.run(
        ["git", "-C", str(repo), "cat-file", "-e", f"{remote}^{{commit}}"], capture_output=True,
    ).returncode == 0
    return f"{remote}..{local}" if known else f"{local} --not --remotes"


def leak_runner(command, **kwargs):
    if command[0] != "docker":
        return run(command, **kwargs)
    code = subprocess.run(command, check=False).returncode
    if code == LEAK_EXIT_CODE:
        raise Findings("Possible secrets in the commits being pushed (shown above, values redacted). "
                       "Remove them, rotate any real key, then push again. "
                       "If it's a false positive, add its fingerprint to .gitleaksignore.")
    if code:
        raise ToolError(f"the secret scan did not complete (exit {code})")


def audit_runner(command, *, cwd=None, **kwargs):
    result = subprocess.run(command + ["--json"], cwd=cwd, capture_output=True, text=True, check=False)
    try:
        report = json.loads(result.stdout)
    except ValueError:
        raise ToolError("pnpm audit returned no readable result") from None
    if "error" in report:
        raise ToolError("pnpm audit could not complete")
    counts = report.get("metadata", {}).get("vulnerabilities", {})
    serious = counts.get("high", 0) + counts.get("critical", 0)
    if serious:
        raise Findings(f"{serious} high/critical vulnerable dependencies in the pushed lockfile. "
                       "Run pnpm audit for details, update them, then push again.")


def warn(stage: str, error: Exception) -> None:
    print(f"MVK: {stage} could not run ({error}). Push allowed; run vaptkit option 3 to check your setup.",
          file=sys.stderr)


def protect(repo: Path, local: str, remote: str | None) -> None:
    revisions = push_revisions(repo, local, remote)
    count = git(repo, "rev-list", "--count", *revisions.split())
    if count == "0":
        return
    print(f"MVK: checking {count} new commit(s) for leaked secrets...", file=sys.stderr, flush=True)
    try:
        scan_history(repo, local, runner=leak_runner, revisions=revisions,
                     leak_exit_code=LEAK_EXIT_CODE, verbose=True)
    except Findings:
        raise
    except (ToolError, OSError) as error:
        warn("the secret scan", error)
    changed = set(git(repo, "log", "--name-only", "--format=", *revisions.split()).splitlines())
    if changed & DEPENDENCY_FILES:
        print("MVK: dependencies changed; auditing for high/critical vulnerabilities...", file=sys.stderr, flush=True)
        try:
            audit_commit(repo, local, runner=audit_runner)
        except Findings:
            raise
        except (ToolError, OSError) as error:
            warn("the dependency audit", error)


def main() -> int:
    try:
        state = json.loads(Path(sys.argv[1]).read_text())
        repo = Path(state["repo"])
        incoming = sys.stdin.read()
        previous = Path(state["previous"]) / "pre-push"
        if previous.is_file() and os.access(previous, os.X_OK):
            launcher = ["sh"] if WINDOWS else []
            result = subprocess.run(
                [*launcher, str(previous), *sys.argv[2:]], input=incoming, text=True, cwd=repo
            )
            if result.returncode:
                raise Findings("Existing pre-push hook failed; push blocked.")
        for local, remote in pushed_updates(incoming):
            protect(repo, local, remote)
        return 0
    except Findings as error:
        print(f"MVK: push blocked. {error}", file=sys.stderr)
        print("MVK: in an emergency, git push --no-verify skips the check.", file=sys.stderr)
        return 1
    except (ToolError, OSError, ValueError) as error:
        warn("the push check", error)
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
