"""One terminal command for independent, supported committed-code checks."""
import json
import os
import re
import random
import shutil
import subprocess
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from collections import Counter
from contextlib import nullcontext

from pyfiglet import Figlet
from rich import box
from rich.align import Align
from rich.console import Console, Group
from rich.panel import Panel
from rich.style import Style
from rich.table import Table
from rich.text import Text

from .assessment import create_output, write_private
from .checks import audit_commit, checked_revision, scan_history, scan_static
from .config import load_config
from .process import ToolError, git
from .routes import review

ACCENT = "#d68b68"
LOADING_LINES = (
    "Checking under the digital sofa...",
    "Asking the bugs to form a queue...",
    "Untangling the suspicious spaghetti...",
    "Consulting the rubber duck council...",
    "Putting on the tiny detective hat...",
    "Turning paranoia into paperwork...",
    "Reading the fine print in the fine print...",
    "Interviewing a very nervous semicolon...",
    "Inspecting the suspiciously quiet corner...",
    "Giving the gremlins a clipboard...",
    "Counting the plot holes...",
    "Following the breadcrumb-shaped bugs...",
    "Checking the pockets of the code...",
    "Asking the skeletons about their closet...",
    "Making eye contact with the TODOs...",
    "Looking behind the magic curtain...",
    "Checking whether the duck has questions...",
    "Opening the drawer labeled 'temporary'...",
    "Measuring the spaghetti by the noodle...",
    "Preparing a strongly worded sticky note...",
    "Looking for the other end of this string...",
    "Taking the scenic route through the syntax...",
    "Asking the exceptions to explain themselves...",
    "Giving the brackets a head count...",
    "Checking the trapdoor under the trapdoor...",
    "Organizing the mystery drawer...",
    "Reading code with one eyebrow raised...",
    "Putting the assumptions on a witness stand...",
    "Looking for duct tape in important places...",
    "Consulting a suspiciously large checklist...",
    "Following the trail of abandoned comments...",
    "Checking the emergency emergency exit...",
    "Asking 'what could possibly go wrong?'...",
    "Counting the layers of 'just this once'...",
    "Taking attendance at the bug meeting...",
    "Offering the race conditions a chair...",
    "Untying a knot with excellent documentation...",
    "Trying to understand past-us...",
    "Asking the edge cases to come inside...",
    "Looking for the manual behind the manual...",
    "Checking the secret compartment's compartment...",
    "Putting a magnifying glass on the magnifying glass...",
    "Making a spreadsheet for the gremlins...",
    "Looking both ways before crossing a callback...",
    "Asking the magic numbers for identification...",
    "Peeking into the box marked 'probably fine'...",
    "Giving the code a politely suspicious look...",
    "Looking for the loose thread in the sweater...",
    "Reading the recipe for this particular spaghetti...",
    "Checking whether 'later' ever happened...",
    "Taking notes for the next rubber duck meeting...",
    "Asking the happy path about its neighbors...",
    "Making room for one more edge case...",
    "Checking the 'nothing to see here' sign...",
    "Inspecting the very professional duct tape...",
    "Looking for the sequel to the workaround...",
    "Asking the comments to match their alibis...",
    "Checking the basement of the abstraction...",
    "Putting the puzzle pieces right-side up...",
    "Looking for the bug wearing a feature costume...",
)


class LoadingMessage:
    def __init__(self, task: str):
        self.task = task
        self.started = time.monotonic()
        self.phrases = random.sample(LOADING_LINES, len(LOADING_LINES))

    def __rich_console__(self, console, options):
        elapsed = max(0, time.monotonic() - self.started)
        phrase = self.phrases[int(elapsed // 4) % len(self.phrases)]
        message = Text(phrase, style=ACCENT)
        message.append(f"  {self.task}  ({elapsed:.0f}s)", style="dim")
        yield message


def print_header(console: Console) -> None:
    width = min(console.width, 60)
    if width < 42:
        content = Group(
            Text("MVK | Matt VAPT Kit", style=f"bold {ACCENT}", justify="center"),
            Text("anti vince vulnerability", justify="center"),
        )
    else:
        rendered = Figlet(font="small", width=60).renderText("M V K")
        wordmark = "\n".join(line.rstrip() for line in rendered.splitlines() if line.strip())
        content = Group(
            Align.center(Text(wordmark, style=f"bold {ACCENT}")),
            Text(""),
            Text("Matt VAPT Kit", style="bold", justify="center"),
            Text("anti vince vulnerability", justify="center"),
        )
    console.print()
    console.print(Align.center(Panel(content, width=width, border_style=ACCENT, padding=(0, 2),
                                     subtitle=Text("COMMITTED-CODE CHECKS", style="dim"))))
    console.print()


def path_link(path: Path, label: str | None = None, *, enabled=True) -> Text:
    resolved = path.resolve()
    display = label if label is not None else str(resolved)
    display = "".join(char if char.isprintable() else "?" for char in display)
    return Text(display,
                style=Style(color=ACCENT, underline=True, link=resolved.as_uri()) if enabled else None)


def static_summary(raw: str, *, errors: list[dict] | None = None) -> list[dict]:
    if len(raw) > 20_000_000:
        raise ToolError("Static output exceeded the size limit; results need a narrower review.")
    try:
        value = json.loads(raw)
        if not isinstance(value, dict) or not isinstance(value.get("results"), list):
            raise ValueError
        processing_errors = value.get("errors", [])
        if not isinstance(processing_errors, list) or any(not isinstance(error, dict) for error in processing_errors):
            raise ValueError
        if processing_errors and errors is None:
            raise ToolError("Static analysis reported processing errors; coverage is incomplete.")
        if errors is not None:
            for error in processing_errors:
                kind = error.get("type", "ProcessingError")
                if not isinstance(kind, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,79}", kind):
                    kind = "ProcessingError"
                errors.append({"type": kind})
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
    print_header(console)
    links = console.is_terminal and not plain
    context = Table.grid(padding=(0, 2))
    context.add_column(style="dim", no_wrap=True)
    context.add_column(overflow="fold")
    context.add_row("Repository", path_link(repo, enabled=links))
    context.add_row("Commit", Text(sha[:12] + "  (working-tree changes excluded)"))
    context.add_row("Save to", path_link(output, enabled=links))
    console.print(context)
    console.print()
    console.print("Scope  ", Text("Committed code only. No live target requests, logins or cloud changes."), style="dim")
    console.print("Network", Text("Image downloads if needed; dependency metadata sent to npm."), style="dim")
    console.print()
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
        console.rule(Text(name, style=f"bold {ACCENT}"), align="left", style="grey37")
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
                console.print(Text("Partial summary: ") + path_link(output / "summary.json", enabled=links))
                raise
            except (ToolError, OSError, subprocess.CalledProcessError) as error:
                detail = str(error) if isinstance(error, ToolError) else "Tool operation failed; raw details withheld."
                row = {"check": name, "status": "REVIEW", "detail": detail}
        rows.append(row)
        color = {"DONE": "green", "REVIEW": "yellow", "NOT RUN": "yellow"}[row["status"]]
        state = Table.grid(padding=(0, 2))
        state.add_column(no_wrap=True)
        state.add_column(overflow="fold")
        state.add_row(Text("  " + row["status"], style=f"bold {color}"), Text(row["detail"]))
        console.print(state)
        console.print()

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
        processing_errors = []
        findings = static_summary(result.stdout, errors=processing_errors)
        incomplete = bool(processing_errors) or result.returncode not in (0, 1) or (result.returncode == 1 and not findings)
        write_private(output / "static-findings.json", json.dumps({
            "revision": sha, "findings": findings, "processing_errors": processing_errors,
            "scanner_exit_code": result.returncode, "status": "incomplete" if incomplete else "completed",
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
        if incomplete:
            raise ToolError(f"{len(findings)} static matches retained; {len(processing_errors)} processing errors "
                            f"(scanner exit {result.returncode}). Coverage incomplete. See static-findings.json.")
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
    table = Table(title="Assessment summary", title_style="bold", header_style="bold",
                  box=box.ROUNDED, border_style=ACCENT, show_lines=True, padding=(0, 1))
    table.add_column("Check", ratio=2)
    table.add_column("Status", no_wrap=True)
    table.add_column("Detail", ratio=4, overflow="fold")
    for row in rows:
        color = "green" if row["status"] == "DONE" else "yellow"
        label = re.sub(r"^\d+ / \d+\s+", "", row["check"])
        table.add_row(Text(label), Text(row["status"], style=f"bold {color}"), Text(row["detail"]))
    table.caption = Text("REVIEW = investigate findings or errors. NOT RUN = a coverage gap.", style="dim")
    console.print()
    console.print(table)
    needs_review = any(row["status"] != "DONE" for row in rows)
    result = {"schema_version": 1, "kind": "repository-scan", "revision": sha,
              "finished_at": datetime.now(timezone.utc).isoformat(), "checks": rows,
              "status": "needs_review" if needs_review else "completed",
              "not_tested": ["live staging", "record ownership", "approval workflows", "live XSS",
                             "Cloud Armor enforcement", "historical breach investigation"]}
    write_private(output / "summary.json", json.dumps(result, indent=2))
    done = sum(row["status"] == "DONE" for row in rows)
    attention = len(rows) - done
    console.print(f"\nFinished in {time.monotonic() - started:.1f}s  |  {done} completed  |  {attention} need attention", style="bold")
    console.print("\nSaved evidence", style=f"bold {ACCENT}")
    evidence = Table.grid(padding=(0, 2))
    evidence.add_column(style="dim", no_wrap=True)
    evidence.add_column(overflow="fold")
    for label, name in (("Summary", "summary.json"), ("Static matches", "static-findings.json"),
                        ("API review", "route-review.json")):
        if (output / name).is_file():
            evidence.add_row(label, path_link(output / name, enabled=links))
    console.print(evidence)
    if links:
        console.print("Paths are terminal links. Use your terminal's open-link gesture (often Ctrl+click).", style="dim")
    console.print("\nNot a live VAPT or an all-clear. Static matches require review.", style="yellow")
    console.print("Next: review saved evidence. Approved staging checks use vapt run / vapt roles.", style="dim")
    return 1 if needs_review else 0
