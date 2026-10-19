"""What a JavaScript/TypeScript project actually uses: files reachable from its entry points, and used packages."""
import json
import re
import subprocess
from pathlib import Path

SOURCE = re.compile(r"\.[cm]?[jt]sx?$")
ENTRY = re.compile(
    r"^(?:src/)?(?:app/(?:.*/)?(?:page|layout|route|loading|error|not-found|template|default|global-error)\.[cm]?[jt]sx?"
    r"|pages/.+\.[cm]?[jt]sx?|middleware\.[cm]?[jt]s|instrumentation\.[cm]?[jt]s)$"
)
CONFIG_ENTRY = re.compile(r"^(?:next|tailwind|postcss|vite|vitest|jest|sentry\.\w+)\.config\.[cm]?[jt]s$|^server\.[cm]?[jt]s$")
SPEC = re.compile(r"""(?:\bfrom\s*|\bimport\s*\(\s*|\brequire\s*\(\s*|^\s*import\s+)['"]([^'"\n]+)['"]""", re.M)


def reachable_files(tree) -> set[str] | None:
    """Source files reachable by imports from Next.js entry points; None when the project has none."""
    sources = [path for path in tree.files if SOURCE.search(path)]
    queue = [path for path in sources if ENTRY.match(path) or CONFIG_ENTRY.match(path)]
    if not any(ENTRY.match(path) for path in queue):
        return None
    seen = set()
    while queue:
        path = queue.pop()
        if path in seen:
            continue
        seen.add(path)
        for spec in SPEC.findall(tree.read(path)):
            target = tree.resolve(path, spec)
            if target and SOURCE.search(target):
                queue.append(target)
    return seen


def unused_dependencies(repo: Path, sha: str, manifest: str = "package.json") -> set[str]:
    """Runtime dependencies whose name appears nowhere in the committed code, configs or package scripts."""
    try:
        package = json.loads(subprocess.run(["git", "-C", str(repo), "show", f"{sha}:{manifest}"],
                                            capture_output=True, text=True, encoding="utf-8",
                                            errors="replace", check=True).stdout)
    except (subprocess.CalledProcessError, ValueError):
        return set()
    names = sorted((package.get("dependencies") or {}).keys())
    if not names:
        return set()
    scripts = " ".join((package.get("scripts") or {}).values())
    patterns = [arg for name in names for arg in ("-e", name)]
    result = subprocess.run(
        ["git", "-C", str(repo), "grep", "-I", "-h", "-o", "-F", *patterns, sha, "--",
         ".", ":!package.json", ":!**/package.json", ":!*lock*", ":!**/*lock*",
         ":!*.md", ":!**/*.md", ":!*.txt", ":!**/*.txt", ":!docs/**", ":!**/docs/**"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    found = set(result.stdout.splitlines())
    return {name for name in names if name not in found and name.split("/")[-1] not in scripts}
