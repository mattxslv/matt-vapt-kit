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
from rich.live import Live
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
LOADING_WORDS = (
    "Bamboozling", "Befuddling", "Bug-hunting", "Burrowing", "Combobulating", "Concocting",
    "Cross-examining", "Decrypting", "Deducing", "Detecting", "Digging", "Disentangling",
    "Dusting", "Excavating", "Fact-checking", "Ferreting", "Fiddling", "Finagling",
    "Flummoxing", "Foraging", "Frisking", "Gumshoeing", "Hmm-ing", "Hunting",
    "Inspecting", "Interrogating", "Investigating", "Jiggling", "Lurking", "Magnifying",
    "Meandering", "Moseying", "Nitpicking", "Noodling", "Nosing", "Patrolling",
    "Peeking", "Perusing", "Pondering", "Poking", "Prodding", "Puzzling",
    "Quizzing", "Rummaging", "Scouring", "Scrutinizing", "Sleuthing", "Sniffing",
    "Snooping", "Spelunking", "Squinting", "Staking-out", "Swabbing", "Tiptoeing",
    "Topsy-turvying", "Triangulating", "Unravelling", "Untangling", "Whittling", "Wrangling",
)
DONE_WORDS = (
    "Baked", "Brewed", "Cooked", "Crunched", "Churned", "Sleuthed", "Simmered", "Stewed",
)
SPINNER_FRAMES = "·✢✳✶✻✽✻✶✳✢"
DECOR_CODE_LINES = (
    "if (user.role !== 'admin') return",
    "const token = crypto.randomBytes(32)",
    "SELECT * FROM sessions WHERE id = ?",
    "export async function middleware(req) {",
    "headers.set('X-Frame-Options', 'DENY')",
    "await bcrypt.compare(password, hash)",
    "process.env.DATABASE_URL ?? 'sqlite://'",
    "app.use(helmet())",
    "const jwt = sign(payload, secret)",
    "if (!authorized) throw new Error('403')",
    "git log --oneline -n 20",
    "docker run --rm --network host ...",
    "grep -rn 'TODO' --include=*.ts .",
    "cookie.secure = true; cookie.httpOnly = true",
    "response.status(401).json({ error })",
    "const hash = sha256(input).hex()",
    "import { NextRequest } from 'next/server'",
    "WHERE created_at > NOW() - INTERVAL '1 day'",
    "openssl x509 -in cert.pem -noout -dates",
    "trustProxy: false, // verify origin",
)
DECOR_WINDOW = 3
DECOR_SECONDS_PER_LINE = 0.6


class LoadingMessage:
    def __init__(self, task: str):
        self.task = re.sub(r"^\d+ / \d+\s+", "", task)
        self.started = time.monotonic()
        self.word = random.choice(LOADING_WORDS)
        self.offset = random.randrange(len(DECOR_CODE_LINES))

    def __rich_console__(self, console, options):
        elapsed = max(0, time.monotonic() - self.started)
        start = self.offset + int(elapsed / DECOR_SECONDS_PER_LINE)
        decor = Text("\n".join(
            DECOR_CODE_LINES[(start + index) % len(DECOR_CODE_LINES)] for index in range(DECOR_WINDOW)
        ), style="dim")
        message = Text(SPINNER_FRAMES[int(elapsed * 8) % len(SPINNER_FRAMES)] + " " + self.word + "…", style=ACCENT)
        message.append(f" ({elapsed:.0f}s · {self.task})", style="dim")
        yield Group(decor, message)


def loading(console: Console, task: str, animate: bool):
    return Live(LoadingMessage(task), console=console, refresh_per_second=8, transient=True) if animate else nullcontext()


def duration(seconds: float) -> str:
    minutes, seconds = divmod(round(seconds), 60)
    return f"{minutes}m {seconds}s" if minutes else f"{seconds}s"


def recap(project: str, rows: list[dict], facts: dict) -> str:
    found = []
    for row in rows:
        stage = re.sub(r"^\d+ / \d+\s+", "", row["check"])
        if row["status"] != "REVIEW":
            continue
        if stage == "Secret history" and facts.get("leaks"):
            found.append(f"{facts['leaks']} possible secrets in its Git history")
        elif stage == "Dependency audit" and facts.get("vulnerabilities"):
            severity = f" ({facts['severity']})" if facts.get("severity") else ""
            found.append(f"{facts['vulnerabilities']} vulnerable packages{severity}")
        elif stage == "Static rules" and facts.get("static"):
            found.append(f"{facts['static']} static-rule matches")
        elif stage == "API authentication review" and facts.get("routes"):
            found.append(f"{facts['routes']} API routes that may be missing auth checks")
        else:
            found.append(f"a {stage.lower()} result that needs a look")
    skipped = [re.sub(r"^\d+ / \d+\s+", "", row["check"]) for row in rows if row["status"] in ("NOT RUN", "CANCELLED")]
    if found:
        listed = found[0] if len(found) == 1 else ", ".join(found[:-1]) + " and " + found[-1]
        text = f"{project} has {listed}."
    else:
        text = f"Nothing was flagged in {project}'s committed code."
    if skipped:
        text += f" {', '.join(skipped)} did not run, so that part is not covered."
    if facts.get("leaks"):
        text += " Next, go through the leaked secrets first: rotate any real key, then add false positives to .gitleaksignore."
    elif facts.get("high"):
        text += " Next, update the packages marked high in the dependency audit."
    elif facts.get("routes"):
        text += " Next, open route-review.json and confirm each flagged route checks the login and role."
    elif facts.get("static"):
        text += " Next, open static-findings.json and check each match."
    elif skipped:
        text += " Next, fix what stopped those checks and scan again."
    else:
        text += " Live staging checks are still separate."
    return text


SHIELD = (
    "  ▄▄▄▄▄  ",
    " █ ▀ ▀ █ ",
    " █  ◆  █ ",
    "  █▀▀▀█  ",
    "   ▀▀▀   ",
)


def print_header(console: Console) -> None:
    width = min(console.width, 60)
    caption = Text(justify="center")
    caption.append("Matt VAPT Kit", style="bold")
    caption.append("\n")
    caption.append("anti vince vulnerability", style="dim")
    caption.append("\n")
    caption.append("to prevent spilling the beans :D", style="dim italic")
    if width < 42:
        content = Group(
            Text("MVK", style=f"bold {ACCENT}", justify="center"),
            Text(""),
            caption,
        )
    else:
        rendered = Figlet(font="ansi_shadow", width=60).renderText("MVK")
        wordmark_lines = [line.rstrip() for line in rendered.splitlines() if line.strip()]
        shield_lines = list(SHIELD)
        pad = len(wordmark_lines) - len(shield_lines)
        blank = " " * len(SHIELD[0])
        shield_lines = [blank] * (pad // 2) + shield_lines + [blank] * (pad - pad // 2)
        lockup = Text()
        for index, (shield_line, wordmark_line) in enumerate(zip(shield_lines, wordmark_lines)):
            if index:
                lockup.append("\n")
            lockup.append(shield_line, style=ACCENT)
            lockup.append("  ")
            lockup.append(wordmark_line, style=f"bold {ACCENT}")
        content = Group(
            Align.center(lockup, width=width),
            Text(""),
            Align.center(caption, width=width),
        )
    console.print()
    console.print(Align.center(content))
    console.print()


def path_link(path: Path, label: str | None = None, *, enabled=True) -> Text:
    resolved = path.resolve()
    display = label if label is not None else str(resolved)
    display = "".join(char if char.isprintable() else "?" for char in display)
    return Text(display,
                style=Style(underline=True, link=resolved.as_uri()) if enabled else None)


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
    facts = {}
    started = time.monotonic()

    def execute(command, *, cwd=None):
        try:
            with subprocess.Popen(command, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                  text=True, errors="replace") as process:
                for line in process.stdout:
                    # Render scanner output literally, without Rich markup or terminal control sequences.
                    clean = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", line.rstrip())
                    clean = "".join(char for char in clean if char == "\t" or char.isprintable())
                    if match := re.search(r"leaks found: (\d+)", clean):
                        facts["leaks"] = int(match[1])
                    if match := re.search(r"(\d+) vulnerabilit(?:y|ies) found", clean):
                        facts["vulnerabilities"] = int(match[1])
                    if match := re.search(r"Severity: (.+)", clean):
                        facts["severity"] = match[1].strip()
                        facts["high"] = bool(re.search(r"\d+ (high|critical)", facts["severity"]))
                    console.print(Text("  " + clean, style="dim"))
                code = process.wait()
        except OSError:
            raise ToolError(f"Cannot start {command[0]}; install it before continuing.") from None
        if code:
            raise ToolError(f"{command[0]} returned exit {code}. Review the output for findings or tooling errors.")

    def stage(name, action, missing=None):
        console.rule(Text(name, style="bold"), align="left", style="grey37")
        if missing:
            row = {"check": name, "status": "NOT RUN", "detail": missing}
        else:
            try:
                with loading(console, name, animate):
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
            with loading(console, "Checking Docker", animate):
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
        facts["static"] = len(findings)
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
        facts["routes"] = count
        if count:
            raise ToolError(f"{count} suspected API authentication findings. Review route-review.json; these are not confirmed exploits.")
        if not summary["handlers"]:
            return "No supported Next.js API handlers found; route review is not applicable."
        return f"{summary['handlers']} handlers reviewed; no suspected authentication gaps reported."
    stage("4 / 4  API authentication review", routes)
    table = Table(title="Assessment summary", title_style="bold", header_style="bold",
                  box=box.ROUNDED, border_style="grey50", show_lines=True, padding=(0, 1))
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
    outcome = f"{attention} need attention" if attention else "all checks done"
    finished = datetime.now().strftime("%I:%M %p").lstrip("0")
    console.print(Text(f"\n✻ {random.choice(DONE_WORDS)} for {duration(time.monotonic() - started)} · done {finished} · "
                       f"{done} completed · {outcome}", style="dim"))
    console.print("\nSaved evidence", style="bold")
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
    console.print()
    console.print(Text("※ recap: ", style="bold dim") + Text(recap(repo.name, rows, facts), style="italic dim"))
    return 1 if needs_review else 0
