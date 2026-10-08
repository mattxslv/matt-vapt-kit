"""One terminal command for independent, supported committed-code checks."""
import json
import os
import re
import random
import shutil
import subprocess
import time
import uuid
from importlib.metadata import version
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
from .checks import audit_commit, checked_revision, lockfiles, scan_history, scan_static, severity_text
from .config import load_config
from .live import (NotCovered, browser_sign_in_possible, run_read_only, standing_approval_path, staging_counts,
                   staging_recap, standing_approval)
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
SHIMMER = "#f3c9b4"
SHIMMER_WIDTH = 3
STEP_WIDTH = 5


class LoadingMessage:
    def __init__(self, task: str):
        step = re.match(r"^(\d+) / (\d+)\s+", task)
        self.step, self.steps = (int(step[1]), int(step[2])) if step else (None, None)
        self.task = re.sub(r"^\d+ / \d+\s+", "", task)
        self.started = time.monotonic()
        self.word = random.choice(LOADING_WORDS)

    def __rich_console__(self, console, options):
        elapsed = max(0, time.monotonic() - self.started)
        message = Text(SPINNER_FRAMES[int(elapsed * 8) % len(SPINNER_FRAMES)] + " ", style=ACCENT)
        word = self.word + "…"
        # A soft highlight sweeps across the word, then pauses off the end before repeating.
        sweep = int(elapsed * 12) % (len(word) + 12) - SHIMMER_WIDTH
        for index, char in enumerate(word):
            message.append(char, style=SHIMMER if sweep <= index < sweep + SHIMMER_WIDTH else ACCENT)
        message.append(f" ({elapsed:.0f}s · {self.task})", style="dim")
        if self.step is None:
            yield message
            return
        track = Text()
        for index in range(1, self.steps + 1):
            if index > 1:
                track.append(" ")
            if index < self.step:
                track.append("━" * STEP_WIDTH, style=ACCENT)
            elif index == self.step:
                track.append("━" * STEP_WIDTH, style=SHIMMER if int(elapsed * 2) % 2 else ACCENT)
            else:
                track.append("─" * STEP_WIDTH, style="grey37")
        track.append(f"  step {self.step} of {self.steps}", style="dim")
        yield Group(message, track)


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
            found.append(f"{facts['vulnerabilities']} known dependency vulnerabilities{severity}")
        elif stage == "Static rules" and facts.get("static"):
            found.append(f"{facts['static']} static-rule matches")
        elif stage == "API authentication review" and facts.get("routes"):
            found.append(f"{facts['routes']} suspected API access-control findings")
        elif stage == "Live staging (read-only)" and facts.get("staging"):
            live = facts["staging"]
            issues = live["confirmed"] + live["suspected"] + live["exposed"]
            found.append(f"{issues} header, cookie or exposed-file issues on live staging" if issues
                         else f"{live['errors']} live staging requests that did not complete")
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
        text += " Next, open route-review.json and confirm each flagged route checks the login, role and record owner."
    elif facts.get("static"):
        text += " Next, open static-findings.json and check each match."
    elif skipped:
        text += " Next, fix what stopped those checks and scan again."
    else:
        text += " Live staging checks are still separate."
    return text


def wordmark_lines() -> list[str]:
    rendered = Figlet(font="ansi_shadow", width=60).renderText("MVK")
    return [line.rstrip() for line in rendered.splitlines() if line.strip()]


def print_header(console: Console) -> None:
    lines = wordmark_lines()
    label = f"v{version('matt-vapt-kit')}"
    width = max(len(line) for line in lines)
    if console.width < width + 2:
        content = Text("MVK", style=f"bold {ACCENT}", justify="center")
        content.append(f" {label}", style="dim")
    else:
        content = Text("\n".join(lines), style=f"bold {ACCENT}")
        content.append("\n" + label.rjust(width), style="dim")
    console.print()
    console.print(Align.center(content))
    console.print()


def path_link(path: Path, label: str | None = None, *, enabled=True) -> Text:
    resolved = path.resolve()
    display = label if label is not None else str(resolved)
    display = "".join(char if char.isprintable() else "?" for char in display)
    return Text(display,
                style=Style(underline=True, link=resolved.as_uri()) if enabled else None)


NON_RUNTIME_DIRS = {"scripts", "script", "migrations", "migration", "seed", "seeds", "tests", "test", "__tests__",
                    "e2e", "cypress", "docs", "doc", "examples", "example", "fixtures", "tools"}
NON_RUNTIME_FILE = re.compile(r"\.(test|spec)\.[cm]?[jt]sx?$|(^|/)(jest|vitest|playwright)\.config\.")


def is_runtime_path(path: str) -> bool:
    """False for one-off scripts, migrations, tests and docs, which never run inside the deployed app."""
    parts = Path(path).parts
    return not (parts and parts[0].lower() in NON_RUNTIME_DIRS
                or any(part.lower() in {"migrations", "__tests__", "fixtures"} for part in parts[:-1])
                or NON_RUNTIME_FILE.search(path))


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
                if isinstance(kind, list) and kind and kind[0] == "PartialParsing":
                    kind = "PartialParsing"
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
            rows.append({"rule": rule, "path": path, "line": line, "verification": "suspected",
                         "runtime": is_runtime_path(path)})
        return rows
    except (ValueError, KeyError, TypeError, AttributeError):
        raise ToolError("Static output was invalid; raw contents withheld.") from None


def scan(repo: Path, *, config_path: Path | None = None, output: Path | None = None,
         console: Console | None = None, plain=False, pdf=False, revision: str = "HEAD",
         branch: str | None = None, live: bool = True, header: bool = True) -> int:
    console = console or Console(highlight=False, no_color=plain or bool(os.environ.get("NO_COLOR")))
    animate = console.is_terminal and not plain and os.environ.get("MVK_REDUCED_MOTION") != "1"
    repo = Path(git(repo, "rev-parse", "--show-toplevel")).resolve()
    sha = checked_revision(repo, revision)
    standing = standing_approval(config_path) if live else None
    total = 5 if standing else 4
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
    if header:
        print_header(console)
    links = console.is_terminal and not plain
    context = Table.grid(padding=(0, 2))
    context.add_column(style="dim", no_wrap=True)
    context.add_column(overflow="fold")
    context.add_row("Repository", path_link(repo, enabled=links))
    if branch:
        context.add_row("Branch", Text(branch))
    context.add_row("Commit", Text(sha[:12] + ("  (working-tree changes excluded)" if revision == "HEAD"
                                               else "  (read from git; your checkout is untouched)")))
    context.add_row("Save to", path_link(output, enabled=links))
    console.print(context)
    console.print()
    if standing and standing["active"]:
        gateway = " (signing in through IAP; header checks only)" if config.get("access") else ""
        scope = (f"Committed code, plus read-only checks of {config['target']['url']}{gateway} under the standing "
                 f"approval until {standing['expires_on']:%Y-%m-%d}. No app logins, attack payloads or cloud changes.")
    else:
        scope = "Committed code only. No live target requests, logins or cloud changes."
    console.print("Scope  ", Text(scope), style="dim")
    console.print("Network", Text("Image downloads if needed; package names and versions sent to osv.dev."), style="dim")
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
            except NotCovered as error:
                row = {"check": name, "status": "NOT RUN", "detail": str(error)}
            except (ToolError, OSError, subprocess.CalledProcessError) as error:
                detail = str(error) if isinstance(error, ToolError) else "Tool operation failed; raw details withheld."
                row = {"check": name, "status": "REVIEW", "detail": detail}
        rows.append(row)
        color = {"DONE": "green", "REVIEW": ACCENT, "NOT RUN": ACCENT}[row["status"]]
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
    stage(f"1 / {total}  Secret history", lambda: scan_history(repo, sha, runner=execute), docker_gap)
    listing = git(repo, "ls-tree", "-r", "--name-only", sha).splitlines()
    def dependencies():
        report = audit_commit(repo, sha)
        if report is None:
            return "No packages found in the committed lockfiles."
        write_private(output / "dependency-audit.json", json.dumps({"revision": sha, **report}, indent=2))
        counts, runtime = report["severity"], report["runtime_severity"]
        serious = runtime["critical"] + runtime["high"]
        dev_serious = counts["critical"] + counts["high"] - serious
        facts.update(vulnerabilities=report["vulnerabilities"], severity=severity_text(counts), high=bool(serious))
        for entry in report["top"][:8]:
            dev = "  (dev only)" if entry["scope"] == "dev" else ""
            console.print(Text(f"  {entry['severity']:<8} {entry['package']} {entry['version']}  {entry['id']}{dev}",
                               style=ACCENT if entry["severity"] in ("critical", "high") and not dev else "dim"))
        if len(report["top"]) > 8:
            console.print(Text(f"  + {len(report['top']) - 8} more", style="dim"))
        lockfile_note = f"{len(report['lockfiles'])} lockfile{'s' if len(report['lockfiles']) != 1 else ''}"
        dev_note = (f" {dev_serious} high/critical are in dev-only packages (tests, build tools) that don't ship."
                    if dev_serious else "")
        if serious:
            raise ToolError(f"{report['vulnerabilities']} known vulnerabilities in {report['packages']} packages "
                            f"({severity_text(counts)}) across {lockfile_note}; {serious} high/critical in runtime "
                            f"dependencies, update those first.{dev_note}")
        if report["vulnerabilities"]:
            return (f"{report['vulnerabilities']} known vulnerabilities ({severity_text(counts)}) across {lockfile_note}; "
                    f"none high or critical in runtime dependencies.{dev_note}")
        return f"No known vulnerabilities in {lockfile_note}."
    found_lockfiles = lockfiles(listing)
    stage(f"2 / {total}  Dependency audit", dependencies,
          docker_gap if found_lockfiles else
          "No supported lockfile (npm, yarn, pnpm, Composer, NuGet, pip, Poetry, Go, Maven, Ruby, Rust) at this commit.")

    def static_command(command, **kwargs):
        try:
            result = subprocess.run(command, capture_output=True, text=True, errors="replace", timeout=180, **kwargs)
        except (OSError, subprocess.TimeoutExpired):
            raise ToolError("Static scanner could not complete; no passing result recorded.") from None
        processing_errors = []
        findings = static_summary(result.stdout, errors=processing_errors)
        runtime = [item for item in findings if item["runtime"]]
        offline = len(findings) - len(runtime)
        facts["static"] = len(runtime)
        # Partial parsing (one JSX snippet skipped) still scans the rest of the file; only real failures leave gaps.
        hard_errors = [error for error in processing_errors if error["type"] != "PartialParsing"]
        partial = len(processing_errors) - len(hard_errors)
        incomplete = bool(hard_errors) or result.returncode not in (0, 1) or (result.returncode == 1 and not findings)
        write_private(output / "static-findings.json", json.dumps({
            "revision": sha, "findings": findings, "processing_errors": processing_errors,
            "scanner_exit_code": result.returncode, "status": "incomplete" if incomplete else "completed",
            "note": "Static matches only, not confirmed vulnerabilities. Source snippets are deliberately omitted.",
        }, indent=2))
        counts = Counter(item["rule"] for item in runtime)
        for rule, count in counts.most_common():
            console.print(Text(f"  {count} matches  {rule}", style=ACCENT))
            locations = list(dict.fromkeys(f"{item['path']}:{item['line']}" for item in runtime if item["rule"] == rule))
            for location in locations[:3]:
                console.print(Text("    " + location, style="dim"))
            if len(locations) > 3:
                console.print(Text(f"    + {len(locations) - 3} more locations in static-findings.json", style="dim"))
        outside = (f" {offline} more in scripts, migrations, tests or docs, which aren't part of the running app."
                   if offline else "")
        partly = f" {partial} file{'s were' if partial != 1 else ' was'} only partly parsed." if partial else ""
        if offline:
            console.print(Text(f"  {offline} matches outside the running app (scripts, migrations, tests, docs)", style="dim"))
        if incomplete:
            raise ToolError(f"{len(runtime)} matches in the running app;{outside} {len(hard_errors)} files couldn't be "
                            f"scanned (scanner exit {result.returncode}), so coverage is incomplete. See static-findings.json.")
        if runtime:
            raise ToolError(f"{len(runtime)} matches in the running app across {len(counts)} rules.{outside}{partly} "
                            "Full locations: static-findings.json. These require review.")
        return f"No matches in the running app.{outside}{partly}".strip()
    stage(f"3 / {total}  Static rules", lambda: scan_static(repo, sha, runner=static_command, json_output=True), docker_gap)

    def routes():
        result = review(repo, config, sha)
        write_private(output / "route-review.json", json.dumps(result, indent=2))
        summary = result["summary"]
        count = len(result["findings"])
        facts["routes"] = count
        ownership = summary.get("ownership", 0)
        protected = summary.get("middleware_protected", 0)
        via_middleware = f" {protected} handlers are protected by the middleware rather than in their own code." if protected else ""
        if count:
            parts = [f"{count - ownership} without a login check" if count - ownership else "",
                     f"{ownership} that change a record chosen by a user ID from the request" if ownership else ""]
            raise ToolError("Suspected access-control findings: " + " and ".join(part for part in parts if part)
                            + f".{via_middleware} Review route-review.json; these are not confirmed exploits.")
        if not summary["handlers"]:
            return "No supported Next.js or ASP.NET handlers found; route review is not applicable."
        return f"{summary['handlers']} handlers reviewed; no suspected access-control gaps.{via_middleware}"
    stage(f"4 / {total}  API authentication review", routes)

    def staging():
        url = config["target"]["url"]
        config_name = config_path.name if config_path else "the project config"
        try:
            result = run_read_only(config, standing, output / "staging")
        except NotCovered:
            raise
        except ToolError as error:
            if config.get("access"):
                raise NotCovered(f"Couldn't sign in to {url} through IAP ({error}). Only accounts on the staging "
                                 "IAP allow-list can run this check.") from None
            raise
        if not result.get("observations"):
            reason = result["errors"][0]["message"] if result["errors"] else "no response."
            raise NotCovered(f"Couldn't reach {url}: {reason} Nothing was checked. If the site moved, update "
                             f"target.url in projects/{config_name}.")
        counts = staging_counts(result)
        facts["staging"] = counts
        facts["staging_covered"] = bool(result.get("observations"))
        if counts["confirmed"] or counts["suspected"] or counts["exposed"] or counts["errors"]:
            raise ToolError(staging_recap(result) + " Evidence: staging/assessment.json.")
        return staging_recap(result)
    if standing:
        expired = (None if standing["active"] else
                   f"The standing approval expired on {standing['expires_on']:%Y-%m-%d}; renew it in "
                   f"projects/{standing_approval_path(config_path).name} to resume live checks.")
        if not expired and config.get("access", {}).get("type") == "iap-browser" and not browser_sign_in_possible():
            expired = ("Staging is behind IAP and needs a browser sign-in, which isn't possible in this automated "
                       "run. Run the scan from the menu on a desktop to include it.")
        stage(f"5 / {total}  Live staging (read-only)", staging, expired)
    table = Table(title="Assessment summary", title_style="bold", header_style="bold",
                  box=box.ROUNDED, border_style="grey50", show_lines=True, padding=(0, 1))
    table.add_column("Check", ratio=2)
    table.add_column("Status", no_wrap=True)
    table.add_column("Detail", ratio=4, overflow="fold")
    for row in rows:
        color = "green" if row["status"] == "DONE" else ACCENT
        label = re.sub(r"^\d+ / \d+\s+", "", row["check"])
        table.add_row(Text(label), Text(row["status"], style=f"bold {color}"), Text(row["detail"]))
    table.caption = Text("REVIEW = investigate findings or errors. NOT RUN = a coverage gap.", style="dim")
    console.print()
    console.print(table)
    needs_review = any(row["status"] != "DONE" for row in rows)
    result = {"schema_version": 1, "kind": "repository-scan", "revision": sha,
              "finished_at": datetime.now(timezone.utc).isoformat(), "checks": rows,
              "status": "needs_review" if needs_review else "completed",
              "not_tested": ([] if facts.get("staging_covered") else ["live staging"]) + [
                  "logged-in pages and role access", "record ownership", "approval workflows", "live XSS",
                  "Cloud Armor enforcement", "historical breach investigation"],
              "target": config.get("target", {}).get("url") if facts.get("staging_covered") else None,
              "project": repo.name, "branch": branch, "facts": facts, "recap": recap(repo.name, rows, facts)}
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
    if pdf:
        from .scan_report import write_scan_report
        write_scan_report(output)
    for label, name in (("Summary", "summary.json"), ("Static matches", "static-findings.json"),
                        ("API review", "route-review.json"), ("Dependencies", "dependency-audit.json"),
                        ("Report", "report.html"), ("PDF report", "report.pdf")):
        if (output / name).is_file():
            evidence.add_row(label, path_link(output / name, enabled=links))
    console.print(evidence)
    if links:
        console.print("Paths are terminal links. Use your terminal's open-link gesture (often Ctrl+click).", style="dim")
    console.print("\nNot a live VAPT or an all-clear. Static matches require review.", style=ACCENT)
    console.print("Next: review saved evidence. Approved staging checks use vapt run / vapt roles.", style="dim")
    console.print()
    console.print(Text("※ recap: ", style="bold dim") + Text(recap(repo.name, rows, facts), style="italic dim"))
    return 1 if needs_review else 0
