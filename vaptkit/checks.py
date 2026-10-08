import json
import os
import re
import subprocess
import tempfile
from pathlib import Path

from .process import ToolError, git, run

GITLEAKS = "ghcr.io/gitleaks/gitleaks@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f"
SEMGREP = "semgrep/semgrep@sha256:acaac22ffc7b7cc5926de0751b223bce0b2491c33d18422fa72f632c78d81198"
SHA = re.compile(r"^[0-9a-f]{40,64}$")
WINDOWS = os.name == "nt"


def user_flag() -> list[str]:
    # Docker Desktop on Windows runs containers in a Linux VM; there is no host uid/gid to map.
    return [] if WINDOWS else ["--user", f"{os.getuid()}:{os.getgid()}"]


def checked_revision(repo: Path, revision: str) -> str:
    sha = git(repo, "rev-parse", "--verify", "--end-of-options", revision + "^{commit}")
    if not SHA.fullmatch(sha):
        raise ToolError("Expected a commit revision.")
    return sha


def docker_repo(repo: Path) -> list[str]:
    common = Path(git(repo, "rev-parse", "--path-format=absolute", "--git-common-dir"))
    command = [
        "docker", "run", "--rm", "--network=none", "--cap-drop=ALL",
        "--security-opt=no-new-privileges", *user_flag(),
        "-e", "HOME=/tmp",
        "-v", f"{repo}:{repo}:ro", "-w", str(repo),
    ]
    if not common.is_relative_to(repo):
        command += ["-v", f"{common}:{common}:ro"]
    return command


def audit_commit(repo: Path, sha: str, *, runner=None) -> None:
    execute = runner or run
    listing = git(repo, "ls-tree", "-r", "--name-only", sha).splitlines()
    if "package.json" not in listing:
        print("Dependency audit: not applicable (no root package.json at this commit).")
        return
    if "pnpm-lock.yaml" not in listing:
        raise ToolError("Node project has no pnpm-lock.yaml; unsupported audit format.")
    package = subprocess.run(
        ["git", "-C", str(repo), "show", f"{sha}:package.json"],
        capture_output=True, check=True,
    ).stdout
    try:
        manager = json.loads(package).get("packageManager", "")
    except (ValueError, AttributeError):
        raise ToolError("Invalid package.json at the pushed commit.") from None
    match = re.fullmatch(r"pnpm@(\d+\.\d+\.\d+)(?:\+sha\d+\.[a-f0-9]+)?", manager)
    if not match:
        raise ToolError("Set an exact pnpm packageManager version before enabling audits.")
    try:
        installed = subprocess.run(
            ["pnpm", "--version"], cwd=repo, capture_output=True, text=True, check=True
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        raise ToolError("pnpm is unavailable. Install the project's pinned version.") from None
    if installed != match[1]:
        raise ToolError(f"Install pnpm {match[1]} for this project before pushing.")
    with tempfile.TemporaryDirectory(prefix="matt-vapt-audit-") as directory:
        root = Path(directory)
        (root / "package.json").write_bytes(package)
        lock = subprocess.run(
            ["git", "-C", str(repo), "show", f"{sha}:pnpm-lock.yaml"],
            capture_output=True, check=True,
        ).stdout
        (root / "pnpm-lock.yaml").write_bytes(lock)
        print("Auditing committed lockfile (package names/versions sent to npm's audit service).")
        execute(["pnpm", "audit", "--audit-level=high", "--registry=https://registry.npmjs.org"], cwd=root)


def check(repo: Path, revision: str, *, static: bool = False) -> None:
    repo = Path(git(repo, "rev-parse", "--show-toplevel")).resolve()
    sha = checked_revision(repo, revision)
    print(f"Checking committed tree {sha[:12]}; dirty working files are not included.", flush=True)
    scan_history(repo, sha)
    audit_commit(repo, sha)
    if static:
        scan_static(repo, sha)


def scan_history(repo: Path, sha: str, *, runner=None, revisions: str | None = None,
                 leak_exit_code: int | None = None, verbose: bool = False) -> None:
    """Gitleaks over the history reachable from sha, or only over `revisions` (git log arguments)."""
    execute = runner or run
    revisions = revisions or sha
    with tempfile.TemporaryDirectory(prefix="matt-vapt-history-") as directory:
        bare = Path(directory) / "history.git"
        # --shared records the host object path, which a Linux container can't resolve on Windows.
        shared = [] if WINDOWS else ["--shared"]
        # A mirror keeps remote-tracking refs, so revisions such as "--not --remotes" still resolve.
        kind = "--bare" if revisions == sha else "--mirror"
        execute(["git", "clone", "--quiet", kind, *shared, str(repo), str(bare)])
        # Honor the committed .gitleaksignore (reviewed historical findings).
        ignore_blob = []
        try:
            content = git(repo, "show", f"{sha}:.gitleaksignore")
            ignore_path = Path(directory) / ".gitleaksignore"
            ignore_path.write_text(content + "\n")
            ignore_blob = ["--gitleaks-ignore-path", str(ignore_path)]
        except ToolError:
            pass
        exit_code = [f"--exit-code={leak_exit_code}"] if leak_exit_code is not None else []
        exit_code += ["--verbose"] if verbose else []
        if WINDOWS:
            execute(windows_history_command(directory, revisions, bool(ignore_blob)) + exit_code)
            return
        execute(docker_repo(repo) + [
            "-v", f"{directory}:{directory}:ro", "-w", str(bare),
            GITLEAKS, "git", str(bare), "--redact", "--no-banner",
            f"--log-opts=--no-textconv --no-ext-diff {revisions}",
        ] + ignore_blob + exit_code)


def windows_history_command(directory: str, revisions: str, has_ignore: bool) -> list[str]:
    """Gitleaks over a standalone bare clone mounted at a fixed Linux path."""
    return [
        "docker", "run", "--rm", "--network=none", "--cap-drop=ALL",
        "--security-opt=no-new-privileges", "-e", "HOME=/tmp",
        # Mounted files are owned by another user inside the VM; git refuses them without this.
        "-e", "GIT_CONFIG_COUNT=1", "-e", "GIT_CONFIG_KEY_0=safe.directory", "-e", "GIT_CONFIG_VALUE_0=*",
        "-v", f"{directory}:/scan:ro", "-w", "/scan/history.git",
        GITLEAKS, "git", "/scan/history.git", "--redact", "--no-banner",
        f"--log-opts=--no-textconv --no-ext-diff {revisions}",
    ] + (["--gitleaks-ignore-path", "/scan/.gitleaksignore"] if has_ignore else [])


def scan_static(repo: Path, sha: str, *, runner=None, json_output=False) -> None:
    execute = runner or run
    # Materialize only this committed tree, never the developer's dirty working files.
    with tempfile.TemporaryDirectory(prefix="matt-vapt-source-") as directory:
        source = Path(directory)
        archive = subprocess.run(
            ["git", "-C", str(repo), "archive", sha], capture_output=True, check=True
        )
        import io
        import tarfile
        with tarfile.open(fileobj=io.BytesIO(archive.stdout)) as tar:
            for member in tar.getmembers():
                if not member.isfile():
                    continue
                relative = Path(member.name)
                if relative.is_absolute() or ".." in relative.parts:
                    raise ToolError("Unsafe path in committed archive.")
                destination = source / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                with tar.extractfile(member) as stream:
                    destination.write_bytes(stream.read())
        rules = Path(__file__).parent / "rules"
        execute([
            "docker", "run", "--rm", "--network=none", "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            *user_flag(), "-e", "HOME=/tmp",
            "-e", "SEMGREP_SEND_METRICS=off", "-e", "SEMGREP_ENABLE_VERSION_CHECK=0",
            "-v", f"{source}:/src:ro", "-v", f"{rules}:/rules:ro",
            "--entrypoint=semgrep", SEMGREP, "scan", "--config=/rules",
            "--metrics=off", "--disable-version-check", "--error",
            "--strict", "--quiet",
        ] + (["--json"] if json_output else []) + ["/src"])


def pushed_updates(lines: str) -> list[tuple[str, str | None]]:
    """(local sha, remote sha or None for a new ref) for each ref a push creates or updates."""
    updates = set()
    for line in lines.splitlines():
        fields = line.split()
        if len(fields) != 4 or not SHA.fullmatch(fields[1]) or not SHA.fullmatch(fields[3]):
            raise ToolError("Invalid pre-push ref input.")
        if set(fields[1]) != {"0"}:
            updates.add((fields[1], None if set(fields[3]) == {"0"} else fields[3]))
    return sorted(updates, key=lambda update: (update[0], update[1] or ""))
