import json
import os
import re
import subprocess
import tempfile
from pathlib import Path

from .process import ToolError, git, run

GITLEAKS = "ghcr.io/gitleaks/gitleaks@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f"
SEMGREP = "semgrep/semgrep@sha256:acaac22ffc7b7cc5926de0751b223bce0b2491c33d18422fa72f632c78d81198"
OSV_SCANNER = "ghcr.io/google/osv-scanner@sha256:afd838850ac1a0fcc15ff4a041dc9ba11123c3f0d2666217a5f0fcf9222b55fa"
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


LOCKFILES = {
    "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock",
    "composer.lock", "requirements.txt", "poetry.lock", "Pipfile.lock", "uv.lock",
    "go.mod", "Gemfile.lock", "Cargo.lock", "pom.xml", "gradle.lockfile",
    "packages.config", "packages.lock.json",
}
PROJECT_FILE_SUFFIXES = (".csproj",)
VENDORED = {"node_modules", "vendor", ".venv", "venv"}
SEVERITIES = ("critical", "high", "medium", "low", "unknown")


def is_lockfile(name: str) -> bool:
    return name in LOCKFILES or name.endswith(PROJECT_FILE_SUFFIXES)


def lockfiles(listing: list[str]) -> list[str]:
    """Committed lockfiles OSV-Scanner understands, skipping vendored dependency folders."""
    return [path for path in listing
            if is_lockfile(Path(path).name) and not VENDORED.intersection(Path(path).parts[:-1])]


def severity_band(score: str) -> str:
    try:
        value = float(score)
    except (TypeError, ValueError):
        return "unknown"
    return "critical" if value >= 9 else "high" if value >= 7 else "medium" if value >= 4 else "low"


def summarize_osv(report: dict) -> dict:
    counts = dict.fromkeys(SEVERITIES, 0)
    top, packages = [], 0
    for result in report.get("results", []):
        for item in result.get("packages", []):
            groups = item.get("groups", [])
            if groups:
                packages += 1
            for group in groups:
                band = severity_band(group.get("max_severity"))
                counts[band] += 1
                package = item["package"]
                top.append({"package": package["name"], "version": package.get("version", ""),
                            "ecosystem": package.get("ecosystem", ""), "id": group["ids"][0], "severity": band,
                            "score": group.get("max_severity") or ""})
    top.sort(key=lambda entry: (SEVERITIES.index(entry["severity"]), entry["package"]))
    return {"vulnerabilities": sum(counts.values()), "packages": packages, "severity": counts, "top": top}


def severity_text(counts: dict) -> str:
    return " | ".join(f"{counts[band]} {band}" for band in SEVERITIES if counts.get(band))


def audit_commit(repo: Path, sha: str) -> dict | None:
    """Check the committed lockfiles against the OSV vulnerability database; None if there are none.

    Only lockfiles are copied out of the commit, so dirty working files never affect the result. Package
    names and versions are sent to osv.dev.
    """
    found = lockfiles(git(repo, "ls-tree", "-r", "--name-only", sha).splitlines())
    if not found:
        return None
    with tempfile.TemporaryDirectory(prefix="matt-vapt-audit-") as directory:
        root = Path(directory)
        for path in found:
            destination = root / path
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(subprocess.run(
                ["git", "-C", str(repo), "show", f"{sha}:{path}"], capture_output=True, check=True,
            ).stdout)
        try:
            result = subprocess.run([
                "docker", "run", "--rm", "--cap-drop=ALL", "--security-opt=no-new-privileges", *user_flag(),
                "-e", "HOME=/tmp", "-v", f"{root}:/src:ro", OSV_SCANNER,
                "scan", "source", "--recursive", "--format", "json", "/src",
            ], capture_output=True, text=True, check=False)
        except OSError:
            raise ToolError("Cannot start docker; install it before continuing.") from None
    if result.returncode == 128:
        return None
    if result.returncode not in (0, 1):
        raise ToolError(f"The dependency scanner did not complete (exit {result.returncode}).")
    try:
        report = json.loads(result.stdout) if result.stdout.strip() else {}
    except ValueError:
        raise ToolError("The dependency scanner returned unreadable output.") from None
    return {**summarize_osv(report), "lockfiles": found}


def check(repo: Path, revision: str, *, static: bool = False) -> None:
    repo = Path(git(repo, "rev-parse", "--show-toplevel")).resolve()
    sha = checked_revision(repo, revision)
    print(f"Checking committed tree {sha[:12]}; dirty working files are not included.", flush=True)
    scan_history(repo, sha)
    report = audit_commit(repo, sha)
    if report is None:
        print("Dependency audit: not applicable (no supported lockfile at this commit).")
    else:
        serious = report["severity"]["critical"] + report["severity"]["high"]
        print(f"Dependency audit: {report['vulnerabilities']} known vulnerabilities in {len(report['lockfiles'])} "
              f"lockfile(s) ({severity_text(report['severity']) or 'none'}).")
        if serious:
            raise ToolError(f"{serious} high/critical dependency vulnerabilities; update those packages.")
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
            # Semgrep's 5s per-file default flakes on large files when the machine is busy.
            "--metrics=off", "--disable-version-check", "--timeout=30", "--error",
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
