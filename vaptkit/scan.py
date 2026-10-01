"""One terminal command for independent, supported committed-code checks."""
import json
import os
import re
import shutil
import subprocess
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from collections import Counter
from contextlib import nullcontext

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .assessment import create_output, write_private
from .checks import audit_commit, checked_revision, scan_history, scan_static
from .config import load_config
from .process import ToolError, git
from .routes import review

ACCENT = "#d68b68"
LOADING_LINES = (
    "Getting the crabs out...",
    "Checking under the digital sofa...",
    "Asking the bugs to form a queue...",
    "Untangling the suspicious spaghetti...",
)


class LoadingMessage:
    def __init__(self, task: str):
        self.task = task
        self.started = time.monotonic()

    def __rich_console__(self, console, options):
        elapsed = max(0, time.monotonic() - self.started)
        phrase = LOADING_LINES[int(elapsed // 4) % len(LOADING_LINES)]
        message = Text(phrase, style=ACCENT)
        message.append(f"  {self.task}  ({elapsed:.0f}s)", style="dim")
        yield message


def static_summary(raw: str) -> list[dict]:
    if len(raw) > 20_000_000:
        raise ToolError("Static output exceeded the size limit; results need a narrower review.")
    try:
        value = json.loads(raw)
        if not isinstance(value, dict) or not isinstance(value.get("results"), list):
            raise ValueError
        if value.get("errors"):
            raise ToolError("Static analysis reported processing errors; coverage is incomplete.")
        rows = []
        for item in value["results"]:
            path = item["path"]
            if path.startswith("/src/"):
                path = path[5:]
            rule = item["check_id"]
            line = item["start"]["line"]
            if (not isinstance(rule, str) or len(rule) > 200 or not path
                    or len(path) > 500 or Path(path).is_absolute() or ".." in Path(path).parts
                    or type(line) is not int or line < 1):
                raise ValueError
            rows.append({"rule": rule, "path": path, "line": line, "verification": "suspected"})
        return rows
    except (ValueError, KeyError, TypeError, AttributeError):
        raise ToolError("Static output was invalid; raw contents withheld.") from None


def scan(repo: Path, *, config_path: Path | None = None, output: Path | None = None,
         console: Console | None = None, plain=False) -> int:
    console = console or Console(highlight=False, no_color=plain or bool(os.environ.get("NO_COLOR")))
    animate = console.is_terminal and not plain and os.environ.get("MVK_REDUCED_MOTION") != "1"
    repo = Path(git(repo, "rev-parse", "--show-toplevel")).resolve()
    sha = checked_revision(repo, "HEAD")
    config = load_config(config_path) if config_path else {
        "project": re.sub(r"[^a-z0-9-]", "-", repo.name.lower()).strip("-")[:64] or "repository",
        "review": {},
    }
    if output is None:
        parent = Path.cwd() / ".private"
        if parent.is_symlink():
            raise ToolError("Use an explicit --output rather than a symlinked .private directory.")
        parent.mkdir(mode=0o700, exist_ok=True)
        parent.chmod(0o700)
        output = parent / ("scan-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6])
    create_output(output)
    title = Text("  \\_(o_o)_/   Matt VAPT Kit\n", style=f"bold {ACCENT}")
    title.append("  Small command. Clear evidence.", style="dim")
    console.print(Panel(title, border_style=ACCENT, expand=False, padding=(1, 2)))
    console.print(Text(f"Repository  {repo}\nRevision    {sha[:12]}\nEvidence    {output.resolve()}"))
    console.print("No live target requests, application logins or cloud changes.", style="yellow")
    console.print("Docker may download pinned scanner images. pnpm audits send package metadata to npm.")
    console.print("Only committed files are checked. Static matches remain suspected until reviewed.\n")
    rows = []
    started = time.monotonic()

    def execute(command, *, cwd=None):
        try:
            with subprocess.Popen(command, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                  text=True, errors="replace") as process:
                for line in process.stdout:
                    # Render scanner output literally, without Rich markup or terminal control sequences.
                    clean = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", line.rstrip())
                    clean = "".join(char for char in clean if char == "\t" or char.isprintable())
                    console.print(Text("  " + clean, style="dim"))
                code = process.wait()
        except OSError:
            raise ToolError(f"Cannot start {command[0]}; install it before continuing.") from None
        if code:
            raise ToolError(f"{command[0]} returned exit {code}. Review the output for findings or tooling errors.")

    def stage(name, action, missing=None):
        console.print(Text("> " + name, style=f"bold {ACCENT}"))
        if missing:
            row = {"check": name, "status": "NOT RUN", "detail": missing}
        else:
            try:
                with (console.status(LoadingMessage(name), spinner="dots", spinner_style=ACCENT,
                                     refresh_per_second=4) if animate else nullcontext()):
                    detail = action()
                row = {"check": name, "status": "DONE", "detail": detail or "No issue reported by this check."}
            except KeyboardInterrupt:
                rows.append({"check": name, "status": "CANCELLED", "detail": "Stopped by the operator."})
                write_private(output / "summary.json", json.dumps({
                    "schema_version": 1, "kind": "repository-scan", "revision": sha,
                    "status": "cancelled", "checks": rows,
                    "note": "Partial results only. Remaining checks were not run.",
                }, indent=2))
                console.print(Text(f"Partial summary: {(output / 'summary.json').resolve()}", style="yellow"))
                raise
            except (ToolError, OSError, subprocess.CalledProcessError) as error:
                detail = str(error) if isinstance(error, ToolError) else "Tool operation failed; raw details withheld."
                row = {"check": name, "status": "REVIEW", "detail": detail}
        rows.append(row)
        color = {"DONE": "green", "REVIEW": "yellow", "NOT RUN": "yellow"}[row["status"]]
        console.print(Text(f"{row['status']}  {row['detail']}\n", style=color))

    docker_ready = False
    if shutil.which("docker"):
        try:
            with (console.status(LoadingMessage("Checking Docker"), spinner="dots", spinner_style=ACCENT,
                                 refresh_per_second=4) if animate else nullcontext()):
                result = subprocess.run(["docker", "info", "--format={{.ServerVersion}}"],
                                        capture_output=True, timeout=15)
            docker_ready = result.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            docker_ready = False
    docker_gap = None if docker_ready else "Docker is unavailable. Start Docker and rerun; remaining independent checks still run."
    stage("1 / 4  Secret history", lambda: scan_history(repo, sha, runner=execute), docker_gap)
    listing = git(repo, "ls-tree", "-r", "--name-only", sha).splitlines()
    def dependencies():
        audit_commit(repo, sha, runner=execute)
        return "High/critical threshold check completed. Lower-severity advisories may still appear above."
    stage("2 / 4  Dependency audit", dependencies,
          None if "package.json" in listing else "No root package.json. Dependency auditing for this ecosystem is not implemented.")

    def static_command(command, **kwargs):
        try:
            result = subprocess.run(command, capture_output=True, text=True, errors="replace", timeout=180, **kwargs)
        except (OSError, subprocess.TimeoutExpired):
            raise ToolError("Static scanner could not complete; no passing result recorded.") from None
        if result.returncode not in (0, 1):
            raise ToolError(f"Static scanner failed (exit {result.returncode}); raw details withheld.")
        findings = static_summary(result.stdout)
        if result.returncode == 1 and not findings:
            raise ToolError("Static scanner exited unsuccessfully without findings; review tooling configuration.")
        write_private(output / "static-findings.json", json.dumps({
            "revision": sha, "findings": findings,
            "note": "Static matches only, not confirmed vulnerabilities. Source snippets are deliberately omitted.",
        }, indent=2))
        counts = Counter(item["rule"] for item in findings)
        for rule, count in counts.most_common():
            console.print(Text(f"  {count} matches  {rule}", style="yellow"))
            locations = list(dict.fromkeys(f"{item['path']}:{item['line']}" for item in findings if item["rule"] == rule))
            for location in locations[:3]:
                console.print(Text("    " + location, style="dim"))
            if len(locations) > 3:
                console.print(Text(f"    + {len(locations) - 3} more locations in static-findings.json", style="dim"))
        if findings:
            raise ToolError(f"{len(findings)} static matches across {len(counts)} rules. Full locations: static-findings.json. These require review.")
    stage("3 / 4  Static rules", lambda: scan_static(repo, sha, runner=static_command, json_output=True), docker_gap)

    def routes():
        result = review(repo, config, sha)
        write_private(output / "route-review.json", json.dumps(result, indent=2))
        summary = result["summary"]
        count = len(result["findings"])
        if count:
            raise ToolError(f"{count} suspected API authentication findings. Review route-review.json; these are not confirmed exploits.")
        if not summary["handlers"]:
            return "No supported Next.js API handlers found; route review is not applicable."
        return f"{summary['handlers']} handlers reviewed; no suspected authentication gaps reported."
    stage("4 / 4  API authentication review", routes)
    table = Table(title="Assessment summary", header_style="bold", box=None, padding=(0, 2))
    table.add_column("Check"); table.add_column("Status"); table.add_column("Detail", overflow="fold")
    for row in rows:
        color = "green" if row["status"] == "DONE" else "yellow"
        table.add_row(Text(row["check"]), Text(row["status"], style=color), Text(row["detail"]))
    console.print(table)
    needs_review = any(row["status"] != "DONE" for row in rows)
    result = {"schema_version": 1, "kind": "repository-scan", "revision": sha,
              "finished_at": datetime.now(timezone.utc).isoformat(), "checks": rows,
              "status": "needs_review" if needs_review else "completed",
              "not_tested": ["live staging", "record ownership", "approval workflows", "live XSS",
                             "Cloud Armor enforcement", "historical breach investigation"]}
    write_private(output / "summary.json", json.dumps(result, indent=2))
    console.print(f"\nFinished in {time.monotonic() - started:.1f}s.", style="bold")
    console.print(Text(f"Private summary: {(output / 'summary.json').resolve()}"))
    console.print("Not a live VAPT or an all-clear. NOT RUN is a coverage gap, not a pass.", style="yellow")
    console.print("For approved staging checks: vapt run / vapt roles. See docs/pilot-checklist.md.")
    return 1 if needs_review else 0
