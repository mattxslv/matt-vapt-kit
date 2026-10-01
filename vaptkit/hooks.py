import json
import os
import shlex
import subprocess
import sys
from pathlib import Path

from .checks import check, pushed_commits
from .process import ToolError, git

MARKER = "# matt-vapt-kit managed hook"


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
    if any(not entry.is_symlink() and entry.name not in allowed for entry in entries):
        raise ToolError("Unexpected files in hooks directory; refusing cleanup.")
    if state["local"] is None:
        git(repo, "config", "--local", "--unset", "core.hooksPath")
    else:
        git(repo, "config", "--local", "core.hooksPath", state["local"])
    for entry in entries:
        entry.unlink()
    destination.rmdir()
    print("Previous Git hook configuration restored.")


def main() -> int:
    try:
        state = json.loads(Path(sys.argv[1]).read_text())
        repo = Path(state["repo"])
        incoming = sys.stdin.read()
        previous = Path(state["previous"]) / "pre-push"
        if previous.is_file() and os.access(previous, os.X_OK):
            result = subprocess.run(
                [str(previous), *sys.argv[2:]], input=incoming, text=True, cwd=repo
            )
            if result.returncode:
                raise ToolError("Existing pre-push hook failed; push blocked.")
        for revision in pushed_commits(incoming):
            check(repo, revision)
        return 0
    except (ToolError, OSError, ValueError) as error:
        print(f"Pre-push check failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
