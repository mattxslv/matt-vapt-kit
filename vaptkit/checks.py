import json
import os
import re
import subprocess
import tempfile
from pathlib import Path

import yaml

from .process import ToolError, git, run
from .usage import unused_dependencies

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


def pnpm_runtime(lock: dict, exclude: frozenset = frozenset(), only: frozenset | None = None) -> set[tuple[str, str]]:
    """(name, version) reachable from the importers' runtime and optional dependencies in a pnpm lockfile.

    `exclude` leaves out direct dependencies (e.g. ones nothing imports); `only` starts from just those names.
    """
    def base(version) -> str:
        return str(version).split("(")[0]

    graph = {}
    for key, info in (lock.get("snapshots") or lock.get("packages") or {}).items():
        name, _, version = key.lstrip("/").split("(")[0].rpartition("@")
        info = info or {}
        graph[(name, version)] = {**info.get("dependencies", {}), **info.get("optionalDependencies", {})}
    queue = []
    for importer in (lock.get("importers") or {".": lock}).values():
        for name, spec in {**(importer.get("dependencies") or {}), **(importer.get("optionalDependencies") or {})}.items():
            if name in exclude or (only is not None and name not in only):
                continue
            queue.append((name, base(spec["version"] if isinstance(spec, dict) else spec)))
    seen = set()
    while queue:
        item = queue.pop()
        if item not in seen:
            seen.add(item)
            queue.extend((name, base(version)) for name, version in graph.get(item, {}).items())
    return seen


def dependency_scopes(root: Path, lockfile: str, unused: frozenset = frozenset()):
    """A function (name, version) -> "runtime" | "unused" | "dev" | "unknown" for one committed lockfile.

    "unused" means reachable only through runtime dependencies nothing in the code imports.
    """
    path, name = root / lockfile, Path(lockfile).name
    try:
        if name == "pnpm-lock.yaml":
            lock = yaml.safe_load(path.read_text()) or {}
            runtime = pnpm_runtime(lock, exclude=unused)
            idle = pnpm_runtime(lock, only=unused) - runtime if unused else set()

            def scope(package, version):
                key = (package, version)
                return "runtime" if key in runtime else "unused" if key in idle else "dev" if runtime else "unknown"
            return scope
        if name in ("package-lock.json", "npm-shrinkwrap.json"):
            entries = json.loads(path.read_text()).get("packages", {})
            scoped = {(key.rpartition("node_modules/")[2], info.get("version")): bool(info.get("dev"))
                      for key, info in entries.items() if key}
            return lambda package, version: ("unknown" if (package, version) not in scoped
                                             else "dev" if scoped[(package, version)] else "runtime")
        if name == "composer.lock":
            dev = {item["name"] for item in json.loads(path.read_text()).get("packages-dev", [])}
            return lambda package, version: "dev" if package in dev else "runtime"
    except (OSError, ValueError, yaml.YAMLError, AttributeError, TypeError):
        pass
    return lambda package, version: "unknown"


def summarize_osv(report: dict, scopes: dict | None = None) -> dict:
    counts = dict.fromkeys(SEVERITIES, 0)
    runtime_counts = dict.fromkeys(SEVERITIES, 0)
    top, packages = [], 0
    for result in report.get("results", []):
        source = result.get("source", {}).get("path", "").removeprefix("/src/")
        scope_of = (scopes or {}).get(source, lambda package, version: "unknown")
        for item in result.get("packages", []):
            groups = item.get("groups", [])
            if groups:
                packages += 1
            for group in groups:
                band = severity_band(group.get("max_severity"))
                package = item["package"]
                scope = scope_of(package["name"], package.get("version", ""))
                counts[band] += 1
                if scope not in ("dev", "unused"):
                    runtime_counts[band] += 1
                top.append({"package": package["name"], "version": package.get("version", ""),
                            "ecosystem": package.get("ecosystem", ""), "id": group["ids"][0], "severity": band,
                            "score": group.get("max_severity") or "", "scope": scope})
    # Runtime (and unclassified) first: dev-only packages never ship in the running app.
    top.sort(key=lambda entry: (entry["scope"] in ("dev", "unused"), SEVERITIES.index(entry["severity"]), entry["package"]))
    return {"vulnerabilities": sum(counts.values()), "packages": packages, "severity": counts,
            "runtime_severity": runtime_counts, "top": top}


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
        has_waiver = False
        try:
            # Same shape as .gitleaksignore below: a committed, reviewed, auditable waiver for a
            # specific advisory (e.g. a transitive dependency with no upstream fix yet), read
            # natively by osv-scanner itself via --config - not a custom format this kit parses or
            # trusts. osv-scanner does NOT auto-detect this file at the scan root; verified against
            # the real pinned image that the flag is required or the waived advisory still blocks.
            (root / "osv-scanner.toml").write_text(git(repo, "show", f"{sha}:osv-scanner.toml") + "\n")
            has_waiver = True
        except ToolError:
            pass
        try:
            result = subprocess.run([
                "docker", "run", "--rm", "--cap-drop=ALL", "--security-opt=no-new-privileges", *user_flag(),
                "-e", "HOME=/tmp", "-v", f"{root}:/src:ro", OSV_SCANNER,
                "scan", "source", "--recursive", "--format", "json",
            ] + (["--config", "/src/osv-scanner.toml"] if has_waiver else []) + ["/src"],
            capture_output=True, text=True, check=False)
        except OSError:
            raise ToolError("Cannot start docker; install it before continuing.") from None
        unused = frozenset(unused_dependencies(repo, sha)) if "package.json" in found or any(
            Path(path).name == "pnpm-lock.yaml" and Path(path).parent == Path(".") for path in found) else frozenset()
        scopes = {path: dependency_scopes(root, path, unused if Path(path).parent == Path(".") else frozenset())
                  for path in found}
        clears = {}
        if unused and "pnpm-lock.yaml" in found:
            lock = yaml.safe_load((root / "pnpm-lock.yaml").read_text()) or {}
            kept = pnpm_runtime(lock, exclude=unused)
            clears = {name: pnpm_runtime(lock, only=frozenset({name})) - kept for name in unused}
    if result.returncode == 128:
        return None
    if result.returncode not in (0, 1):
        raise ToolError(f"The dependency scanner did not complete (exit {result.returncode}).")
    try:
        report = json.loads(result.stdout) if result.stdout.strip() else {}
    except ValueError:
        raise ToolError("The dependency scanner returned unreadable output.") from None
    summary = summarize_osv(report, scopes)
    serious = [(entry["package"], entry["version"]) for entry in summary["top"]
               if entry["scope"] == "unused" and entry["severity"] in ("critical", "high")]
    summary["unused_dependencies"] = sorted(
        ({"name": name, "clears": sum(1 for key in serious if key in closure)} for name, closure in clears.items()),
        key=lambda item: -item["clears"])
    return {**summary, "lockfiles": found}


PROJECTS_DIR = Path(__file__).resolve().parent.parent / "projects"


def project_config_for(repo: Path) -> Path | None:
    """The projects/*.vapt.yml whose name best matches this repo's folder name, if any."""
    if not PROJECTS_DIR.is_dir():
        return None
    name = repo.name.lower()
    matches = [path for path in PROJECTS_DIR.glob("*.vapt.yml") if path.name.removesuffix(".vapt.yml") in name]
    return max(matches, key=lambda path: len(path.name), default=None)


def check(repo: Path, revision: str, *, static: bool = False, routes: bool = False) -> None:
    repo = Path(git(repo, "rev-parse", "--show-toplevel")).resolve()
    sha = checked_revision(repo, revision)
    print(f"Checking committed tree {sha[:12]}; dirty working files are not included.", flush=True)
    found = history_findings(repo, sha)
    real = [item for item in found if not item["placeholder"]]
    placeholders = len(found) - len(real)
    note = f" {placeholders} more look like placeholders in docs or example values." if placeholders else ""
    print(f"Secret history: {len(real)} possible secrets (values withheld).{note}" if found
          else "Secret history: no issue reported by this check.")
    if real:
        raise ToolError(f"{len(real)} possible secrets in the Git history (values withheld).{note} "
                        "Rotate any that are real, even if later deleted.")
    report = audit_commit(repo, sha)
    if report is None:
        print("Dependency audit: not applicable (no supported lockfile at this commit).")
    else:
        serious = report["runtime_severity"]["critical"] + report["runtime_severity"]["high"]
        total = report["severity"]["critical"] + report["severity"]["high"]
        # Lead with what's actually reachable: a raw "2 critical | 62 high" overstates risk when most of it
        # is dev-only or comes only through a dependency nothing imports.
        print(f"Dependency audit: {serious} high/critical in runtime dependencies"
              + (f" (of {total} total across {report['packages']} packages)" if total != serious else "")
              + f". {report['vulnerabilities']} known vulnerabilities in {len(report['lockfiles'])} lockfile(s) "
              f"({severity_text(report['severity']) or 'none'}).")
        if serious:
            raise ToolError(f"{serious} high/critical vulnerabilities in runtime dependencies; update those packages.")
    if static:
        scan_static(repo, sha)
    if routes:
        config_path = project_config_for(repo)
        if config_path is None:
            print("API access-control review: not applicable (no matching project config).")
        else:
            from .config import load_config
            from .routes import review
            result = review(repo, load_config(config_path), sha)
            summary = result["summary"]
            protected = f", {summary['middleware_protected']} protected by middleware" if summary.get("middleware_protected") else ""
            print(f"API access-control review: {summary['handlers']} handlers reviewed{protected}.")
            if result["findings"]:
                for item in result["findings"][:8]:
                    print(f"  [{item['severity'].upper():6}] {item['path']}  {item['title']}")
                raise ToolError(f"{len(result['findings'])} suspected API access-control findings; see the detail above.")


def clone_history(repo: Path, bare: Path, execute) -> None:
    # A mirror copies every ref, including remote-tracking branches, so scanning origin/main from a staging
    # checkout finds its commits even without --shared (which Windows can't use: it records host paths).
    shared = [] if WINDOWS else ["--shared"]
    execute(["git", "clone", "--quiet", "--mirror", *shared, str(repo), str(bare)])


PLACEHOLDER_VALUE = re.compile(r"(?i)your[_-]|example|sample|dummy|placeholder|changeme|change[_-]me|fake|lorem"
                               r"|x{4,}|abc|123456|<[^>]*>|\*{3,}|\.\.\.|test[_-]?(?:token|key|secret|password)")
DOC_FILE = re.compile(r"(?i)\.(?:md|mdx|markdown|rst|adoc|txt)$|(?:^|/)docs?/")


def history_findings(repo: Path, sha: str) -> list[dict]:
    """Gitleaks matches in the history reachable from sha, as metadata only.

    Matched values are inspected in memory to recognize documentation placeholders, then dropped: they are never
    stored or printed. Each result keeps rule, file, line, short commit and the .gitleaksignore fingerprint.
    """
    with tempfile.TemporaryDirectory(prefix="matt-vapt-history-") as directory:
        bare = Path(directory) / "history.git"
        clone_history(repo, bare, run)
        has_ignore = False
        try:
            (Path(directory) / ".gitleaksignore").write_text(git(repo, "show", f"{sha}:.gitleaksignore") + "\n")
            has_ignore = True
        except ToolError:
            pass
        if WINDOWS:
            command = windows_history_command(directory, sha, has_ignore)
        else:
            command = docker_repo(repo) + [
                "-v", f"{directory}:{directory}:ro", "-w", str(bare), GITLEAKS, "git", str(bare), "--no-banner",
                f"--log-opts=--no-textconv --no-ext-diff {sha}",
            ] + (["--gitleaks-ignore-path", str(Path(directory) / ".gitleaksignore")] if has_ignore else [])
        command = [arg for arg in command if arg != "--redact"] + ["--report-format", "json", "--report-path", "-"]
        try:
            result = subprocess.run(command, capture_output=True, text=True, check=False)
        except OSError:
            raise ToolError("Cannot start docker; install it before continuing.") from None
    if result.returncode not in (0, 1):
        raise ToolError(f"The secret scanner did not complete (exit {result.returncode}).")
    try:
        raw = json.loads(result.stdout) if result.stdout.strip() else []
    except ValueError:
        raise ToolError("The secret scanner returned unreadable output.") from None
    findings = [{
        "rule": item.get("RuleID", ""), "file": item.get("File", ""), "line": item.get("StartLine"),
        "commit": (item.get("Commit") or "")[:12], "fingerprint": item.get("Fingerprint", ""),
        "placeholder": bool(DOC_FILE.search(item.get("File", "")) or PLACEHOLDER_VALUE.search(item.get("Secret", ""))),
    } for item in raw]
    raw.clear()
    return findings


def scan_history(repo: Path, sha: str, *, runner=None, revisions: str | None = None,
                 leak_exit_code: int | None = None, verbose: bool = False) -> None:
    """Gitleaks over the history reachable from sha, or only over `revisions` (git log arguments)."""
    execute = runner or run
    revisions = revisions or sha
    with tempfile.TemporaryDirectory(prefix="matt-vapt-history-") as directory:
        bare = Path(directory) / "history.git"
        clone_history(repo, bare, execute)
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
