"""Compare scans of two branches: findings open on one but not the other, and security commits on one side only."""
import json
import re
from pathlib import Path

from .process import git

SECURITY_COMMIT = re.compile(
    r"(?i)secur|vuln|cve-|ghsa-|\bauth(?:entication|orization|orize|orise)?\b|xss|csrf|sqli|inject|vapt|cert-?ph|leak|secret|harden|ownership|idor"
    r"|permission|\brole|sanitiz|escape|\bpatch|\bbump|upgrade|dependenc|404|rate.?limit|header|cookie|session"
)
COMMIT_LIMIT = 15


def read(folder: Path, name: str) -> dict:
    path = folder / name
    return json.loads(path.read_text()) if path.is_file() else {}


def finding_keys(folder: Path) -> dict[str, dict]:
    """Comparable identity -> description for every finding a scan folder recorded."""
    keys = {}
    for item in read(folder, "route-review.json").get("findings", []):
        method = item.get("method", "")
        keys[f"route|{item['title']}|{item['path']}"] = {"kind": "Access control", "what": item["title"],
                                                         "where": f"{method} {item['path']}" if method else item["path"],
                                                         "file": item.get("impact", "").split(" handler in ")[-1].split(". ")[0]}
    for item in read(folder, "static-findings.json").get("findings", []):
        if item.get("runtime", True):
            keys[f"static|{item['rule']}|{item['path']}"] = {"kind": "Code rule", "what": item["rule"],
                                                              "where": item["path"], "file": item["path"]}
    advisories = {}
    for item in read(folder, "dependency-audit.json").get("top", []):
        if item.get("scope") != "dev" and item["severity"] in ("critical", "high"):
            advisories.setdefault((item["package"], item["version"]), []).append(item["id"])
    for (package, version), ids in advisories.items():
        keys[f"dep|{package}|{version}"] = {"kind": "Dependency", "what": f"{package} {version}",
                                            "where": f"{len(ids)} high/critical advisor{'ies' if len(ids) != 1 else 'y'}",
                                            "file": None}
    for item in read(folder, "secret-findings.json").get("findings", []):
        if not item.get("placeholder"):
            keys[f"secret|{item['rule']}|{item['file']}"] = {"kind": "Secret", "what": item["rule"],
                                                              "where": item["file"], "file": item["file"]}
    return keys


DOC_ONLY = re.compile(r"(?i)\.(?:md|mdx|txt|rst)$|(?:^|/)docs?/")
KIND_ORDER = {"Access control": 0, "Secret": 1, "Code rule": 2, "Dependency": 3}


def security_commits(repo: Path, base: str, tip: str) -> list[str]:
    """Security-looking commits in base..tip, skipping ones that only touch documentation."""
    found = []
    for line in git(repo, "log", "--no-merges", "--format=%h %s", f"{base}..{tip}").splitlines():
        if not SECURITY_COMMIT.search(line):
            continue
        files = git(repo, "diff-tree", "--no-commit-id", "--name-only", "-r", line.split()[0]).splitlines()
        if files and not all(DOC_ONLY.search(path) for path in files):
            found.append(line)
            if len(found) == COMMIT_LIMIT:
                break
    return found


def fixes_for(repo: Path, open_on: str, fixed_on: str, file: str | None) -> list[str]:
    """Commits on the fixing branch, not on the other, that touched the finding's file."""
    if not file or "/" not in file and "." not in file:
        return []
    return git(repo, "log", "--no-merges", "--format=%h %s", f"{open_on}..{fixed_on}", "--", file).splitlines()[:3]


def build_drift(repo: Path, scans: list[tuple[str, Path]]) -> dict:
    """Drift between the first two (branch, scan folder) pairs."""
    (left_name, left), (right_name, right) = scans[:2]
    left_sha = read(left, "summary.json")["revision"]
    right_sha = read(right, "summary.json")["revision"]
    left_keys, right_keys = finding_keys(left), finding_keys(right)

    def side(open_keys, other_keys, open_sha, other_sha):
        items = [{**open_keys[key], "fix_commits": fixes_for(repo, open_sha, other_sha, open_keys[key]["file"])}
                 for key in set(open_keys) - set(other_keys)]
        return sorted(items, key=lambda item: (KIND_ORDER[item["kind"]], item["what"], item["where"]))

    return {
        "branches": [left_name, right_name], "revisions": [left_sha, right_sha],
        "open_only_on": {left_name: side(left_keys, right_keys, left_sha, right_sha),
                         right_name: side(right_keys, left_keys, right_sha, left_sha)},
        "security_commits_only_on": {left_name: security_commits(repo, right_sha, left_sha),
                                     right_name: security_commits(repo, left_sha, right_sha)},
    }


def render_markdown(drift: dict, project: str) -> str:
    left, right = drift["branches"]
    lines = [f"# Branch drift · {project}", "",
             f"Compared `{left}` ({drift['revisions'][0][:12]}) with `{right}` ({drift['revisions'][1][:12]}).", ""]
    for branch, other in ((left, right), (right, left)):
        items = drift["open_only_on"][branch]
        lines += [f"## Open on {branch}, not on {other} ({len(items)})", ""]
        lines += [f"- **{item['kind']}:** {item['what']} · {item['where']}"
                  + (f"  \n  Fixed on {other} by: " + "; ".join(f"`{commit}`" for commit in item["fix_commits"])
                     if item["fix_commits"] else "") for item in items] or ["- None"]
        lines.append("")
    for branch, other in ((left, right), (right, left)):
        commits = drift["security_commits_only_on"][branch]
        lines += [f"## Security-related commits only on {branch} ({len(commits)})", ""]
        lines += [f"- `{commit}`" for commit in commits] or ["- None"]
        lines.append("")
    lines.append("Findings are compared by what and where; a fix on the other branch is a commit there that touched "
                 "the same file. Check each one before porting it.")
    return "\n".join(lines) + "\n"
