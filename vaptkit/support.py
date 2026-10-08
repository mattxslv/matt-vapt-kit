"""Problem reports: diagnostics a teammate can send to the maintainer, never findings or secrets."""
import getpass
import os
import platform
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from importlib.metadata import version
from pathlib import Path
from urllib.parse import urlencode

DEFAULT_REPO = "mattxslv/matt-vapt-kit"
URL_LIMIT = 7000


def state_dir() -> Path:
    return Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local/state") / "matt-vapt-kit"


def last_error_file() -> Path:
    return state_dir() / "last-error.txt"


def sanitize(text: str) -> str:
    """Hide the home folder and username, which show up in paths."""
    home = str(Path.home())
    text = text.replace(home, "~").replace(home.replace("\\", "/"), "~")
    user = getpass.getuser()
    if len(user) > 2:
        text = re.sub(rf"(?i)\b{re.escape(user)}\b", "<user>", text)
    return text


def record_error(where: str, detail: str) -> None:
    """Keep the most recent problem so a report can include it. Best effort: never raises."""
    try:
        path = last_error_file()
        path.parent.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        path.write_text(sanitize(f"{stamp} · {where}\n{detail.strip()[-3000:]}\n"))
    except OSError:
        pass


def tool_version(command: list[str]) -> str:
    if not shutil.which(command[0]):
        return "not installed"
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired):
        return "did not respond"
    output = (result.stdout or result.stderr).strip().splitlines()
    return output[0][:120] if result.returncode == 0 and output else f"error (exit {result.returncode})"


def repo_slug(kit: Path) -> str:
    try:
        url = subprocess.run(["git", "-C", str(kit), "remote", "get-url", "origin"],
                             capture_output=True, text=True, timeout=10).stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return DEFAULT_REPO
    match = re.search(r"github\.com[:/]([\w.-]+/[\w.-]+?)(?:\.git)?$", url)
    return match[1] if match else DEFAULT_REPO


def diagnostics(checks: list[tuple[str, bool, str]], protected: int) -> str:
    last = last_error_file().read_text().strip() if last_error_file().is_file() else "none recorded"
    lines = [
        "## Environment",
        f"- Kit: v{version('matt-vapt-kit')}",
        f"- OS: {platform.platform()}",
        f"- Python: {sys.version.split()[0]}",
        f"- Git: {tool_version(['git', '--version'])}",
        f"- Docker: {tool_version(['docker', 'version', '--format', '{{.Server.Version}}'])}",
        f"- Push protection: on for {protected} recent project{'s' if protected != 1 else ''}",
        "",
        "## Readiness",
        *[f"- {'OK' if ready else 'MISSING'} {name}: {detail}" for name, ready, detail in checks],
        "",
        "## Last problem",
        "```",
        last,
        "```",
    ]
    return sanitize("\n".join(lines))


def issue_url(repo: str, title: str, body: str) -> str:
    """A pre-filled 'new issue' link; the body is shortened to stay within browser URL limits."""
    base = f"https://github.com/{repo}/issues/new?"
    note = "\n\n_(Shortened to fit the link; the full report was saved on the reporter's machine.)_"
    text, keep = body, len(body)
    while len(base + urlencode({"title": title, "body": text})) > URL_LIMIT and keep > 200:
        keep = int(keep * 0.8)
        text = body[:keep].rstrip() + note
    return base + urlencode({"title": title, "body": text, "labels": "pilot-report"})
