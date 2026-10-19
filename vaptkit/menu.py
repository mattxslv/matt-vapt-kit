"""Numbered terminal menu for the committed-code scan and its results."""
import contextlib
import getpass
import io
import platform
import traceback
import webbrowser
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from importlib.metadata import version
from pathlib import Path
from urllib.parse import urlsplit

from rich import box
from rich.console import Console
from rich.padding import Padding
from rich.table import Table
from rich.text import Text

from .assessment import approval_template, assess
from .checks import project_config_for
from .config import ConfigError, load_config
from .doctor import diagnose
from .hooks import install as install_hook
from .drift import build_drift, render_markdown
from .live import staging_recap
from .native_scan import nuclei_binary, run_nuclei_native, run_zap_native, zap_binary
from .support import diagnostics, issue_url, record_error, repo_slug, sanitize
from .process import ToolError, git, stream
from .report import generate as generate_report
from .scan import ACCENT, dated_folder, path_link, print_header, project_slug, scan
from .scan_report import pdf_available, write_scan_report
from .yamlutil import safe_dump

KIT = Path(__file__).resolve().parent.parent
PRIVATE = KIT / ".private"
RECENT_LIMIT = 8
WINDOWS = os.name == "nt"
SEARCH_DEPTH = 4
SKIP_DIRS = {"node_modules", "AppData", "Library", "snap", "venv", "site-packages", "vendor", "go", "Downloads"}


UPDATE_CHECK_INTERVAL = timedelta(hours=24)


def update_check_file() -> Path:
    return Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local/state") / "matt-vapt-kit/update-check.json"


def git_output(*args: str, timeout: float = 5.0) -> str:
    result = subprocess.run(["git", "-C", str(KIT), *args], capture_output=True, text=True, timeout=timeout,
                            env={**os.environ, "GIT_TERMINAL_PROMPT": "0"})
    return result.stdout.strip() if result.returncode == 0 else ""


def check_for_update() -> str | None:
    """A one-line notice if this install is behind origin/main, or None.

    Cached for `UPDATE_CHECK_INTERVAL` so the menu doesn't hit the network on every launch; any
    failure (offline, no git, not this kit's own repo) is silent, never blocks startup.
    """
    state_path = update_check_file()
    now = datetime.now(timezone.utc)
    try:
        state = json.loads(state_path.read_text()) if state_path.is_file() else {}
    except (OSError, ValueError):
        state = {}
    checked_at = state.get("checked_at")
    if checked_at:
        try:
            if now - datetime.fromisoformat(checked_at) < UPDATE_CHECK_INTERVAL:
                return state.get("message")
        except ValueError:
            pass
    message = None
    try:
        git_output("fetch", "--quiet", "origin", "main", timeout=5)
        local = git_output("rev-parse", "HEAD")
        remote = git_output("rev-parse", "origin/main")
        if local and remote and local != remote:
            ahead = git_output("rev-list", "--count", f"{local}..{remote}")
            if ahead.isdigit() and int(ahead) > 0:
                message = (f"A new matt-vapt-kit version is available ({ahead} commit"
                          f"{'s' if ahead != '1' else ''} behind main) - run `git pull` then `./install`.")
    except (OSError, subprocess.TimeoutExpired):
        message = None
    try:
        state_path.parent.mkdir(parents=True, exist_ok=True)
        state_path.write_text(json.dumps({"checked_at": now.isoformat(), "message": message}))
    except OSError:
        pass
    return message


def recent_file() -> Path:
    return Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local/state") / "matt-vapt-kit/recent-projects.json"


def load_recent() -> list[str]:
    path = recent_file()
    if not path.is_file():
        return []
    return [entry for entry in json.loads(path.read_text()) if Path(entry).is_dir()]


def remember(repo: Path) -> None:
    entries = [str(repo)] + [entry for entry in load_recent() if entry != str(repo)]
    path = recent_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(entries[:RECENT_LIMIT], indent=2))


def matching_config(repo: Path) -> Path | None:
    return project_config_for(repo)


def ask(console: Console, prompt: str) -> str:
    return console.input(Text(prompt, style="bold")).strip()


def pause(console: Console) -> None:
    ask(console, "\nPress Enter to go back to the menu...")


def retry_input(console: Console, prompt: str, parse):
    """Ask for input, retrying on parse() raising ToolError. Typing b/back cancels (returns None)."""
    while True:
        entry = ask(console, prompt)
        if entry.lower() in ("b", "back"):
            return None
        try:
            return parse(entry)
        except ToolError as error:
            console.print(Text(f"{error} (type b to go back to the menu)", style=ACCENT))


def option(console: Console, key: str, label: str) -> None:
    line = Text()
    line.append(f"  {key:>2}  ", style="bold")
    line.append(label, style="default")
    console.print(line)


def project_list() -> list[tuple[Path, bool]]:
    """[(project, recently used)]: recent projects first, then every other Git project in the home folder."""
    recent = [Path(entry) for entry in load_recent()]
    seen = {path.resolve() for path in recent}
    others = [repo for repo in find_repos(Path.home()) if repo.resolve() not in seen]
    return [(path, True) for path in recent] + [(path, False) for path in others]


def choose_project(console: Console) -> Path | None:
    projects = project_list()
    console.print(Text("Which project?", style="bold"))
    last_recent = None
    for number, (path, recent) in enumerate(projects, start=1):
        if recent != last_recent:
            console.print(Text("  Recent" if recent else "  Other projects found on this computer", style="dim"))
            last_recent = recent
        label = str(path).replace(str(Path.home()), "~", 1)
        option(console, str(number), label)
    if projects:
        console.print()
    option(console, "n", "Type a different folder path")
    option(console, "b", "Back")
    choice = ask(console, "\nChoose: ").lower()
    if choice.isdigit() and 1 <= int(choice) <= len(projects):
        return projects[int(choice) - 1][0]
    if choice == "n":
        typed = ask(console, "Project folder (for example ~/DTAP): ")
        return Path(typed).expanduser() if typed else None
    return None


COMMON_BRANCHES = ("main", "master", "staging", "develop", "dev")


def refresh_branches(repo: Path) -> bool:
    """git fetch without credential prompts, so a missing login can't hang the menu."""
    try:
        result = subprocess.run(["git", "-C", str(repo), "fetch", "--quiet", "--prune"], capture_output=True,
                                timeout=60, env={**os.environ, "GIT_TERMINAL_PROMPT": "0"})
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def branch_choices(repo: Path) -> list[tuple[str, str]]:
    """[(label, revision)]: your checkout first, then common branches from origin, without checking anything out.

    Used by the full scan (option 0), which deliberately stays scoped to the usual handful of
    long-lived branches rather than every feature branch that happens to exist on origin.
    """
    current = git(repo, "rev-parse", "--abbrev-ref", "HEAD")
    choices = [(f"{current} (your checkout)" if current != "HEAD" else "your checkout", "HEAD")]
    remote = set(git(repo, "for-each-ref", "--format=%(refname:short)", "refs/remotes/origin").splitlines())
    for name in COMMON_BRANCHES:
        if name != current and f"origin/{name}" in remote:
            choices.append((name, f"origin/{name}"))
    return choices


def all_branch_choices(repo: Path) -> list[tuple[str, str]]:
    """[(label, revision)]: your checkout first, then every other branch on origin, for manual picking."""
    current = git(repo, "rev-parse", "--abbrev-ref", "HEAD")
    choices = [(f"{current} (your checkout)" if current != "HEAD" else "your checkout", "HEAD")]
    remote = sorted(name.removeprefix("origin/") for name in
                    git(repo, "for-each-ref", "--format=%(refname:short)", "refs/remotes/origin").splitlines()
                    if name != "origin/HEAD")
    common_first = [name for name in COMMON_BRANCHES if name in remote and name != current]
    rest = [name for name in remote if name != current and name not in COMMON_BRANCHES]
    for name in common_first + rest:
        choices.append((name, f"origin/{name}"))
    return choices


def pick_branches(console: Console, choices: list[tuple[str, str]]) -> list[tuple[str, str]] | None:
    console.print(Text("\nWhich branch?", style="bold"))
    for number, (label, _) in enumerate(choices, start=1):
        option(console, str(number), label)
    option(console, "a", "All of the above, one report each")
    picked = retry_input(console, "\nChoose [1] (or b to go back): ",
                         lambda entry: [0] if not entry.strip() else parse_selection(entry, len(choices)))
    return None if picked is None else [choices[index] for index in picked]


def prepare_project(console: Console) -> Path | None:
    """Pick a project, confirm it's a Git repo, remember it and refresh its remote branches."""
    repo = choose_project(console)
    if repo is None:
        return None
    try:
        repo = Path(git(repo, "rev-parse", "--show-toplevel")).resolve()
    except ToolError:
        console.print(Text(f"\n{repo} is not a Git project folder.", style=ACCENT))
        pause(console)
        return None
    remember(repo)
    console.print(Text("\nChecking the remote for the latest branches...", style="dim"))
    if not refresh_branches(repo):
        console.print(Text("Couldn't reach the remote; using the branches already on this computer.", style=ACCENT))
    return repo


def scan_branches(console: Console, repo: Path, selected: list[tuple[str, str]]) -> list[tuple[str, Path]]:
    """Scan each (label, revision) into its own evidence folder; returns [(branch label, folder)] that finished."""
    config = matching_config(repo)
    PRIVATE.mkdir(mode=0o700, exist_ok=True)
    console.clear()
    finished = []
    for index, (label, revision) in enumerate(selected):
        branch = label.removesuffix(" (your checkout)")
        output = dated_folder(PRIVATE, "scan", repo.name, branch)
        if index:
            console.rule(Text(f"Next: {branch}", style="bold"), style="grey37")
        try:
            # The live staging check is about the deployed site, not a branch, so run it once per run.
            scan(repo, config_path=config, output=output, console=console, revision=revision,
                 branch=branch if len(selected) > 1 or revision != "HEAD" else None, live=index == 0,
                 header=index == 0)
        except KeyboardInterrupt:
            console.print(Text("\nScan stopped.", style=ACCENT))
            break
        except ToolError as error:
            record_error("scan", str(error))
            console.print(Text(f"\n{error}", style=ACCENT))
            console.print(Text("If this looks like a problem with the kit, choose 8 to report it.", style="dim"))
        else:
            finished.append((branch, output))
    return finished


def show_drift(console: Console, repo: Path, finished: list[tuple[str, Path]]) -> None:
    """Compare the first two branch scans, print the headline and save the full report."""
    try:
        drift = build_drift(repo, finished)
    except (ToolError, OSError, KeyError, ValueError) as error:
        record_error("branch drift", str(error))
        console.print(Text(f"\nCouldn't compare the branches: {error}", style=ACCENT))
        return
    folder = dated_folder(PRIVATE, "drift", repo.name)
    folder.mkdir(mode=0o700)
    (folder / "drift.json").write_text(json.dumps(drift, indent=2))
    (folder / "drift.md").write_text(render_markdown(drift, repo.name))
    left, right = drift["branches"]
    console.print(Text(f"\nBranch drift · {left} vs {right}", style="bold"))
    for branch, other in ((left, right), (right, left)):
        items = drift["open_only_on"][branch]
        important = [item for item in items if item["kind"] != "Dependency"]
        deps = len(items) - len(important)
        line = Text(f"  Open on {branch}, fixed on {other}: ", style="bold")
        line.append(f"{len(important)} findings" + (f" + {deps} vulnerable packages" if deps else ""),
                    style=ACCENT if items else "green")
        console.print(line)
        for item in important[:5]:
            fix = f"  ← fix on {other}: {item['fix_commits'][0]}" if item["fix_commits"] else ""
            console.print(Text(f"    {item['kind']}: {item['what']} · {item['where']}{fix}"[:150], style="dim"))
    for branch in (left, right):
        commits = drift["security_commits_only_on"][branch]
        if commits:
            console.print(Text(f"  Security-related commits only on {branch}: {len(commits)}", style="bold"))
            for commit in commits[:4]:
                console.print(Text(f"    {commit}"[:120], style="dim"))
    console.print(Text("Full drift report: ") + path_link(folder / "drift.md"))


def run_scan(console: Console) -> None:
    repo = prepare_project(console)
    if repo is None:
        return
    selected = pick_branches(console, all_branch_choices(repo))
    if not selected:
        return
    scanned = scan_branches(console, repo, selected)
    finished = [folder for _, folder in scanned]
    needs_pause = True
    if len(finished) == 1:
        needs_pause = offer_scan_pdf(console, finished[0])
    elif finished:
        if ask(console, f"\nMake PDF reports for all {len(finished)} branches? (y/N): ").lower() == "y":
            for folder in finished:
                offer_scan_pdf(console, folder, confirm=False, open_prompt=False)
        if len(scanned) > 1:
            show_drift(console, repo, scanned)
            console.print()
            console.rule(Text("Scan complete", style="bold green"), style="grey37")
    if needs_pause:
        pause(console)


def full_scan(console: Console) -> None:
    """Everything for one project with no further questions: every branch, live check, all PDFs, one summary."""
    repo = prepare_project(console)
    if repo is None:
        return
    finished = scan_branches(console, repo, branch_choices(repo))
    if not finished:
        pause(console)
        return
    reports = []
    for branch, folder in finished:
        try:
            html, pdf = write_scan_report(folder, html_only=not pdf_available())
        except (ToolError, OSError) as error:
            record_error("full scan PDF", str(error))
            html, pdf = folder / "report.html", None
        reports.append((branch, folder, pdf if pdf else html if html.is_file() else None))
    table = Table(title=f"Full scan · {repo.name}", title_style="bold", header_style="bold",
                  box=box.ROUNDED, border_style="grey50", padding=(0, 1))
    for column in ("Branch", "Needs attention", "Secrets", "High/critical deps (runtime)", "Access control", "Report"):
        table.add_column(column, overflow="fold")
    for branch, folder, report in reports:
        summary = json.loads((folder / "summary.json").read_text())
        facts = summary.get("facts", {})
        attention = sum(row["status"] != "DONE" for row in summary["checks"])
        audit = folder / "dependency-audit.json"
        audit_data = json.loads(audit.read_text()) if audit.is_file() else {}
        runtime = audit_data.get("runtime_severity", audit_data.get("severity", {}))
        total = audit_data.get("severity", {})
        serious = runtime.get("critical", 0) + runtime.get("high", 0)
        dev_only = total.get("critical", 0) + total.get("high", 0) - serious
        table.add_row(branch, Text(str(attention), style=ACCENT if attention else "green"),
                      str(facts.get("leaks", 0)), f"{serious}" + (f" (+{dev_only} dev)" if dev_only else ""),
                      str(facts.get("routes", 0)),
                      path_link(report, report.name) if report else Text("not made", style=ACCENT))
    console.print()
    console.print(table)
    if len(finished) > 1:
        show_drift(console, repo, [(branch, folder) for branch, folder in finished])
    if not pdf_available():
        console.print(Text(PDF_TOOLS_HINT, style=ACCENT))
    console.print()
    console.rule(Text("Scan complete", style="bold green"), style="grey37")
    console.print(Text("Reports list findings; share them only with people approved to see them.", style="dim"))
    if offer_open(console, [report for *_, report in reports if report], [folder for _, folder, _ in reports]):
        pause(console)


def open_path(console: Console, path: Path) -> None:
    if WINDOWS:
        os.startfile(path)
    elif shutil.which("xdg-open"):
        subprocess.Popen(["xdg-open", str(path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    else:
        console.print(Text("xdg-open is not available; open the path above manually.", style=ACCENT))


PDF_TOOLS_HINT = "The PDF tools aren't installed, so only the HTML version was made. Re-run ./install (or install.ps1) to add them."


def offer_open(console: Console, reports: list[Path], folders: list[Path]) -> bool:
    """Let the user open the report files, the folders holding all the evidence, or neither.

    Returns True if something was opened, so the caller knows whether a further
    "press Enter to continue" prompt is still needed or would just be a second one.
    """
    report_word = "report" + ("s" if len(reports) > 1 else "")
    folder_word = "folder" + ("s" if len(folders) > 1 else "")
    console.print()
    option(console, "r", f"Open the {report_word}")
    option(console, "f", f"Open the {folder_word}")
    option(console, "b", "Open both")
    choice = ask(console, "\nChoose (or Enter to go back): ").lower()
    paths = (reports + folders if choice == "b" else
             reports if choice == "r" else folders if choice == "f" else [])
    if paths:
        word = f"{report_word} and {folder_word}" if choice == "b" else report_word if choice == "r" else folder_word
        console.print(Text(f"Opening {len(paths)} {word}...", style="dim"))
    for path in paths:
        open_path(console, path)
    return bool(paths)


def show_report(console: Console, html: Path, pdf: Path | None, *, open_prompt: bool = True) -> bool:
    """Returns True if the caller still needs to pause before returning to the menu."""
    console.print(Text("\nReport saved: ", style="bold") + path_link(pdf or html))
    if pdf is None:
        console.print(Text(PDF_TOOLS_HINT, style=ACCENT))
    console.print(Text("It lists findings; share it only with people approved to see them.", style="dim"))
    if not open_prompt:
        return True
    return not offer_open(console, [pdf or html], [html.parent])


def offer_scan_pdf(console: Console, folder: Path, *, confirm: bool = True, open_prompt: bool = True) -> bool:
    """Returns True if the caller still needs to pause before returning to the menu."""
    existing = next((folder / name for name in ("report.pdf", "report.html") if (folder / name).is_file()), None)
    if existing:
        console.print(Text("\nThis scan already has a report: ") + path_link(existing))
        return True
    if confirm and ask(console, "\nMake a PDF report of this scan? (y/N): ").lower() != "y":
        return True
    try:
        html, pdf = write_scan_report(folder, html_only=not pdf_available())
    except ToolError as error:
        console.print(Text(f"\n{error}", style=ACCENT))
        if (folder / "report.html").is_file():
            console.print(Text("HTML report: ") + path_link(folder / "report.html"))
        return True
    return show_report(console, html, pdf, open_prompt=open_prompt)


def latest_scan() -> Path | None:
    scans = sorted(PRIVATE.glob("scan-*/summary.json"))
    return scans[-1].parent if scans else None


def list_scans() -> list[Path]:
    return sorted(path.parent for path in PRIVATE.glob("scan-*/summary.json"))


def scan_findings(folder: Path) -> tuple[set[tuple], set[str]]:
    """(static-rule findings, API routes with no authentication) recorded in a scan folder."""
    static_path = folder / "static-findings.json"
    static_findings = set()
    if static_path.is_file():
        data = json.loads(static_path.read_text())
        static_findings = {(item["rule"], item["path"], item["line"]) for item in data.get("findings", [])}
    route_path = folder / "route-review.json"
    no_auth_routes = set()
    if route_path.is_file():
        data = json.loads(route_path.read_text())
        no_auth_routes = {route["path"] for route in data.get("routes", [])
                           if any(not handler["authentication"] for handler in route["handlers"])}
    return static_findings, no_auth_routes


def compare_scans(older: Path, newer: Path) -> dict:
    old_static, old_routes = scan_findings(older)
    new_static, new_routes = scan_findings(newer)
    return {
        "new_static": sorted(new_static - old_static),
        "resolved_static": sorted(old_static - new_static),
        "new_no_auth_routes": sorted(new_routes - old_routes),
        "resolved_no_auth_routes": sorted(old_routes - new_routes),
    }


def show_compare(console: Console) -> None:
    scans = list_scans()
    if len(scans) < 2:
        console.print(Text("\nNeed at least two scans to compare. Run another scan first.", style=ACCENT))
        pause(console)
        return
    older, newer = scans[-2], scans[-1]
    diff = compare_scans(older, newer)
    console.print()
    console.print(Text(f"Comparing {older.name}  ->  {newer.name}", style="bold"))

    def section(title: str, items: list, color: str) -> None:
        if not items:
            return
        console.print(Text(f"\n{title} ({len(items)})", style=f"bold {color}"))
        for item in items[:20]:
            text = item if isinstance(item, str) else " ".join(f"{part}:" if index == 0 else str(part)
                                                                 for index, part in enumerate(item))
            console.print(Text("  " + text, style=color))
        if len(items) > 20:
            console.print(Text(f"  ... and {len(items) - 20} more", style="dim"))

    section("New static-rule matches", diff["new_static"], ACCENT)
    section("Resolved static-rule matches", diff["resolved_static"], "green")
    section("API routes newly missing authentication", diff["new_no_auth_routes"], ACCENT)
    section("API routes that now have authentication", diff["resolved_no_auth_routes"], "green")
    if not any(diff.values()):
        console.print(Text("\nNo change in static matches or no-authentication routes between these two scans.", style="dim"))
    pause(console)


def show_latest(console: Console) -> None:
    folder = latest_scan()
    if folder is None:
        console.print(Text("\nNo scans yet. Choose 1 to run one.", style=ACCENT))
        pause(console)
        return
    summary = json.loads((folder / "summary.json").read_text())
    table = Table(title="Latest scan", title_style="bold", header_style="bold",
                  box=box.ROUNDED, border_style="grey50", show_lines=True, padding=(0, 1))
    table.add_column("Check", ratio=2)
    table.add_column("Status", no_wrap=True)
    table.add_column("Detail", ratio=4, overflow="fold")
    for row in summary["checks"]:
        color = "green" if row["status"] == "DONE" else ACCENT
        label = row["check"].split("  ", 1)[-1]
        table.add_row(Text(label), Text(row["status"], style=f"bold {color}"), Text(row["detail"]))
    console.print()
    console.print(table)
    console.print(Text(f"Finished {summary.get('finished_at', 'unknown')}  |  commit {summary['revision'][:12]}", style="dim"))
    console.print(Text("Saved in ") + path_link(folder))
    console.print()
    option(console, "p", "Make a PDF report of this scan")
    option(console, "t", "Export findings as a remediation-ticket table (Markdown)")
    option(console, "o", "Open this folder")
    option(console, "b", "Back")
    choice = ask(console, "\nChoose: ").lower()
    if choice == "p":
        if offer_scan_pdf(console, folder, confirm=False):
            pause(console)
    elif choice == "t":
        export_tickets(console, folder)
        pause(console)
    elif choice == "o":
        open_path(console, folder)


def export_tickets(console: Console, folder: Path) -> None:
    from .certph import render_markdown
    destination = folder / "tickets.md"
    try:
        destination.write_text(render_markdown(folder))
    except (ToolError, OSError) as error:
        record_error("ticket export", str(error))
        console.print(Text(f"\n{error}", style=ACCENT))
        return
    console.print(Text("\nTicket table saved: ") + path_link(destination))
    console.print(Text("Field names are a best-effort mapping, not a verified CERT-PH template; check them before "
                       "pasting this into a report.", style="dim"))


HOSTNAME = re.compile(r"^[a-z0-9]+([.-][a-z0-9]+)*$")


def staging_config(url: str) -> dict:
    parsed = urlsplit(url.strip() if "://" in url else "https://" + url.strip())
    host = (parsed.hostname or "").lower()
    if not host or not HOSTNAME.fullmatch(host):
        raise ToolError("Enter a URL such as https://staging.example.gov.ph")
    return {
        "schema_version": 1,
        "project": "quick-" + "-".join(host.split(".")[:2])[:50] or "quick-staging",
        "target": {
            "environment": "staging",
            "url": f"https://{host}",
            "allowed_hosts": [host],
            "verification": "reachable-not-authorized",
        },
        "scope": {"api_prefixes": ["/api/"], "excluded_prefixes": [], "roles": []},
        "credentials": {},
    }


def run_staging_check(console: Console) -> None:
    console.print(Text("Quick staging check", style="bold"))
    console.print(Text("Safe, read-only checks: security headers, cookies, and a short list of commonly "
                       "exposed files/endpoints (.env, .git/HEAD, debug endpoints, source maps).", style="dim"))
    console.print(Text("Login-protected sites (for example anything behind Google IAP) are not supported here.", style="dim"))
    config = retry_input(console, "\nStaging URL (or b to go back): ", staging_config)
    if config is None:
        return
    console.print(Text(f"\nThis will send a small number of HEAD/GET requests to {config['target']['url']}.", style=ACCENT))
    if ask(console, "Do you have permission to test this site? (y/N): ").lower() != "y":
        console.print(Text("\nStopped. Get permission from the site owner first.", style=ACCENT))
        pause(console)
        return
    approver = ask(console, f"Your name [{getpass.getuser()}]: ") or getpass.getuser()
    minutes_raw = ask(console, "Test window in minutes, 1-240 [60]: ") or "60"
    try:
        minutes = max(1, min(240, int(minutes_raw)))
    except ValueError:
        minutes = 60
    PRIVATE.mkdir(mode=0o700, exist_ok=True)
    base = dated_folder(PRIVATE, config["project"])
    config_path = base.with_suffix(".vapt.yml")
    config_path.write_text(safe_dump(config, sort_keys=False))
    config_path.chmod(0o600)
    try:
        config = load_config(config_path)
    except ConfigError as error:
        console.print(Text(f"\n{error}", style=ACCENT))
        pause(console)
        return
    now = datetime.now(timezone.utc)
    approval = approval_template(config)
    approval.update({
        "approved_by": approver,
        "starts_at": now.isoformat(),
        "expires_at": (now + timedelta(minutes=minutes)).isoformat(),
        "exposure_checks": True,
        "paths": ["/"],
    })
    output = base
    console.print(Text(f"\nChecking {config['target']['url']} for up to {minutes} minute(s)..."))
    try:
        path, code = assess(config, approval, output)
    except ToolError as error:
        console.print(Text(f"\n{error}", style=ACCENT))
        pause(console)
        return
    result = json.loads(path.read_text())
    console.print(Text(f"\nStatus: {result['status']}", style="bold"))
    console.print(Text(f"Saved to {output}", style="dim"))
    console.print()
    console.print(Text("※ recap: ", style="bold dim") + Text(staging_recap(result), style="italic dim"))
    needs_pause = True
    if ask(console, "\nMake a PDF report of this check? (y/N): ").lower() == "y":
        html_only = not pdf_available()
        try:
            html = generate_report(path, output / "report", reviewed=True, html_only=html_only)
        except ToolError as error:
            console.print(Text(f"\n{error}", style=ACCENT))
        else:
            needs_pause = show_report(console, html, None if html_only else html.with_name("report.pdf"))
    if needs_pause:
        pause(console)


LOCAL_HOSTS = ("localhost", "127.0.0.1")
NUCLEI_TIMEOUT_SECONDS = 600
# With host networking, templates that hardcode their own port (e.g. Spark UI on 4040) would probe
# other services on this machine. Keep to HTTP templates and drop those that pin a port.
NUCLEI_SCRIPT = (
    'nuclei -update-templates -silent >/dev/null 2>&1; '
    'find /root/nuclei-templates -name "*.yaml" | xargs grep -lE '
    '"\\{\\{(BaseURL|RootURL|Host|Hostname)\\}\\}:[0-9]{2,5}" > /tmp/fixed-port-templates.txt; '
    'exec nuclei -u "$1" -pt http -exclude-templates /tmp/fixed-port-templates.txt '
    '-severity low,medium,high,critical -c 10 -o /output/nuclei.txt'
)
ZAP_NOISE = re.compile(r"^\d+ \[\S+\] |^Found Java version|^Available memory:|^Using JVM args:")


def is_noisy_zap_line(line: str) -> bool:
    """True for ZAP's raw Java boot/logging lines, not its scan findings or errors."""
    return bool(ZAP_NOISE.match(line))
ZAP_TIMEOUT_SECONDS = 900
# DOM XSS (40026) drives Firefox inside the container; it doesn't fit the memory cap and stalls every scan.
ZAP_RULES = "40026\tIGNORE\t(DOM XSS needs a browser that does not fit the memory cap)\n"
ZAP_ALERT = re.compile(r"^(WARN|FAIL)-NEW: .*\[\d+\]", re.MULTILINE)


def zap_alert_count(log: str) -> int:
    """Alert lines such as 'WARN-NEW: Missing header [10021] x 3', not ZAP's final totals line."""
    return len(ZAP_ALERT.findall(log))


def is_local_target(url: str) -> bool:
    parsed = urlsplit(url)
    return parsed.hostname in LOCAL_HOSTS and bool(parsed.scheme) and parsed.port is not None


def container_target(url: str) -> tuple[str, list[str]]:
    """The URL scanner containers should use for a local app, and the docker network flags to reach it."""
    if not WINDOWS:
        return url, ["--network", "host"]
    # Docker Desktop runs containers in a VM, where localhost is the VM itself; this name is the Windows host.
    parsed = urlsplit(url)
    return parsed._replace(netloc=f"host.docker.internal:{parsed.port}").geturl(), []


def local_url(entry: str) -> str:
    """Accept a bare port, host:port, or a full URL and normalize to http://localhost:PORT."""
    entry = entry.strip() or "3000"
    if entry.isdigit():
        entry = f"http://localhost:{entry}"
    elif "://" not in entry:
        entry = "http://" + entry
    if not is_local_target(entry):
        raise ToolError("Enter a port (3000), a host:port (localhost:3000) or a full URL (http://localhost:3000).")
    return entry


LOW_MEMORY_MB = 4096


def available_memory_mb() -> int | None:
    """Available RAM in MiB from /proc/meminfo, or None if it can't be read (non-Linux)."""
    try:
        with open("/proc/meminfo") as handle:
            for line in handle:
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1]) // 1024
    except (OSError, ValueError, IndexError):
        return None
    return None


def run_local_attack(console: Console) -> None:
    console.print(Text("Local attack testing", style="bold"))
    console.print(Text("Runs active security scanners (Nuclei, OWASP ZAP) against an app running on "
                       "this machine. These send real test payloads, not just observations.", style="dim"))
    console.print(Text("Only use this on a disposable local copy with synthetic data, never on staging "
                       "or production.", style=ACCENT))
    url = retry_input(console, "\nLocal port or URL [3000] (or b to go back): ", local_url)
    if url is None:
        return
    if ask(console, "This app is running locally and it's OK to attack-test it now? (y/N): ").lower() != "y":
        console.print(Text("\nStopped; nothing was run.", style="dim"))
        pause(console)
        return
    docker_available = bool(shutil.which("docker"))
    nuclei_bin = None if docker_available else nuclei_binary()
    zap_bin = None if docker_available else zap_binary()
    if not docker_available and not nuclei_bin and not zap_bin:
        console.print(Text("\nDocker is required for local attack testing (or install Nuclei and/or "
                           "ZAP natively and make sure they're on PATH).", style=ACCENT))
        pause(console)
        return
    available = available_memory_mb()
    if available is not None and available < LOW_MEMORY_MB:
        console.print(Text(f"\nOnly {available} MiB RAM is free; these scanners can make the machine "
                           "slow or unresponsive. Close other apps first.", style=ACCENT))
        if ask(console, "Continue anyway? (y/N): ").lower() != "y":
            console.print(Text("\nStopped; nothing was run.", style="dim"))
            pause(console)
            return
    PRIVATE.mkdir(mode=0o700, exist_ok=True)
    output = dated_folder(PRIVATE, "attack", url)
    output.mkdir(mode=0o700)
    console.clear()
    print_header(console)
    target, network = container_target(url) if docker_available else (url, [])
    console.print(Text(f"Target   {url}", style="dim"))
    if target != url:
        console.print(Text(f"Scanners reach it as {target} (Docker Desktop's name for this computer).", style="dim"))
    if not docker_available:
        console.print(Text(f"Running natively (no Docker): "
                           f"{'Nuclei' if nuclei_bin else '-'} / {'ZAP' if zap_bin else '-'}.", style="dim"))
    console.print(Text(f"Save to  {output}", style="dim"))
    console.print(Text("Each scanner is capped on memory and time so a slow machine doesn't need "
                       "to be force-stopped.", style="dim"))
    console.print()

    def printer(line):
        console.print(Text("  " + line, style="dim"))

    def zap_printer(line):
        if not is_noisy_zap_line(line):
            printer(line)

    def stop(name):
        def callback():
            subprocess.run(["docker", "kill", name], capture_output=True)
        return callback

    summary = []
    console.rule(Text("1 / 2  Nuclei known-issue scan", style="bold"), align="left", style="grey37")
    if docker_available:
        nuclei_name = f"mvk-nuclei-{stamp}"
        nuclei_log, code, nuclei_timed_out = stream([
            "docker", "run", "--rm", *network, "--name", nuclei_name,
            "--memory=1g", "--memory-swap=1g",
            "-v", f"{output}:/output", "--entrypoint", "sh",
            next(image for image in LOCAL_ATTACK_IMAGES if "nuclei" in image),
            "-c", NUCLEI_SCRIPT, "sh", target,
        ], printer, timeout=NUCLEI_TIMEOUT_SECONDS, on_timeout=stop(nuclei_name))
    elif nuclei_bin:
        nuclei_log, code, nuclei_timed_out = run_nuclei_native(
            nuclei_bin, target, output, printer, timeout=NUCLEI_TIMEOUT_SECONDS, on_timeout=None)
    else:
        nuclei_log, code, nuclei_timed_out = "", None, False
    if code is None:
        summary.append("Nuclei: skipped (not installed; install Nuclei natively or install Docker).")
        nuclei_style = "dim"
    else:
        hits = len((output / "nuclei.txt").read_text().splitlines()) if (output / "nuclei.txt").is_file() else 0
        if nuclei_timed_out:
            summary.append(f"Nuclei: stopped after {NUCLEI_TIMEOUT_SECONDS // 60} minute(s); {hits} matched issue(s) so far.")
        else:
            summary.append(f"Nuclei: {hits} matched issue(s)." if code == 0 else "Nuclei: scan did not complete; see nuclei.txt.")
        nuclei_style = "bold " + (ACCENT if hits or code else "green")
    console.print(Text(f"  {summary[-1]}", style=nuclei_style))
    console.print()

    console.rule(Text("2 / 2  ZAP active scan", style="bold"), align="left", style="grey37")
    if docker_available:
        zap_name = f"mvk-zap-{stamp}"
        (output / "zap-rules.conf").write_text(ZAP_RULES)
        zap_log, code, zap_timed_out = stream([
            "docker", "run", "--rm", *network, "--name", zap_name,
            "--memory=2g", "--memory-swap=2g", "-e", "JAVA_OPTS=-Xmx1536m",
            "-v", f"{output}:/zap/wrk:rw",
            next(image for image in LOCAL_ATTACK_IMAGES if "zap" in image),
            "zap-full-scan.py", "-t", target, "-r", "zap-report.html", "-c", "zap-rules.conf", "-I", "-s",
        ], zap_printer, timeout=ZAP_TIMEOUT_SECONDS, on_timeout=stop(zap_name))
    elif zap_bin:
        zap_log, code, zap_timed_out = run_zap_native(
            zap_bin, target, output, zap_printer, timeout=ZAP_TIMEOUT_SECONDS, on_timeout=None)
    else:
        zap_log, code, zap_timed_out = "", None, False
    if code is None:
        summary.append("ZAP: skipped (not installed; install ZAP natively or install Docker).")
        zap_style = "dim"
    else:
        alerts = zap_alert_count(zap_log)
        if zap_timed_out:
            summary.append(f"ZAP: stopped after {ZAP_TIMEOUT_SECONDS // 60} minute(s); partial results may be in zap-report.html.")
        else:
            summary.append(f"ZAP: {alerts} alert(s) raised." if (output / "zap-report.html").is_file() else "ZAP: scan did not complete.")
        zap_style = "bold " + (ACCENT if alerts or zap_timed_out else "green")
    console.print(Text(f"  {summary[-1]}", style=zap_style))

    console.print()
    console.print(Text("Saved evidence", style="bold"))
    for name in ("nuclei.txt", "zap-report.html"):
        if (output / name).is_file():
            console.print(Text("  ") + path_link(output / name))
    console.print()
    console.print(Text("※ recap: ", style="bold dim") + Text(" ".join(summary) + (
        " Review the saved reports; matches are suspected issues, not confirmed exploits."
        if any("0" not in line for line in summary) else ""), style="italic dim"))
    pause(console)


LOCAL_ATTACK_IMAGES = {
    "projectdiscovery/nuclei:latest": "Nuclei",
    "ghcr.io/zaproxy/zaproxy:stable": "ZAP",
}


def missing_local_attack_images() -> list[str]:
    return [image for image in LOCAL_ATTACK_IMAGES
            if subprocess.run(["docker", "image", "inspect", image], capture_output=True).returncode != 0]


def find_repos(root: Path, depth: int = SEARCH_DEPTH) -> list[Path]:
    """Git projects under root, newest activity first, without descending into a project once found."""
    found = []
    def walk(folder: Path, level: int) -> None:
        try:
            entries = list(os.scandir(folder))
        except OSError:
            return
        if any(entry.name == ".git" for entry in entries):
            found.append(folder)
            return
        if level == depth:
            return
        for entry in entries:
            if entry.is_dir(follow_symlinks=False) and not entry.name.startswith(".") and entry.name not in SKIP_DIRS:
                walk(Path(entry.path), level + 1)
    walk(root, 0)
    return sorted(found, key=lambda repo: (repo / ".git").stat().st_mtime, reverse=True)


def is_protected(repo: Path) -> bool:
    return (repo / ".git" / "matt-vapt-hooks").is_dir()


def parse_selection(entry: str, count: int) -> list[int]:
    """'a' for all, or numbers like '1 3 5' / '1,3' / '2-4'; returns zero-based indexes."""
    entry = entry.strip().lower()
    if entry in ("a", "all"):
        return list(range(count))
    picked = set()
    for part in entry.replace(",", " ").split():
        start, _, end = part.partition("-")
        if not start.isdigit() or (end and not end.isdigit()):
            raise ToolError("Type numbers like 1 3 5 or 2-4, a for all, or b to go back.")
        first, last = int(start), int(end or start)
        if not 1 <= first <= last <= count:
            raise ToolError(f"Pick numbers between 1 and {count}, separated by spaces (for example 1 2 3 4, or 1-4).")
        picked.update(range(first - 1, last))
    if not picked:
        raise ToolError("Type numbers like 1 3 5 or 2-4, a for all, or b to go back.")
    return sorted(picked)


def protect_pushes(console: Console) -> None:
    console.print(Text("Push protection", style="bold"))
    console.print(Text("Before each git push, checks the new commits for leaked secrets and, if dependencies "
                       "changed, for high/critical vulnerable packages. Findings block the push; if the check "
                       "can't run (for example Docker is off) it warns and lets the push through.", style="dim"))
    console.print(Text("\nLooking for Git projects in your home folder...", style="dim"))
    repos = find_repos(Path.home())
    if not repos:
        console.print(Text("No Git projects found. Clone a project first, then come back here.", style=ACCENT))
        pause(console)
        return
    console.print()
    for number, repo in enumerate(repos, start=1):
        label = str(repo).replace(str(Path.home()), "~", 1)
        option(console, str(number), label + ("  (already protected)" if is_protected(repo) else ""))
    console.print(Text("\nProjects cloned later are not covered; come back to this option to add them.", style="dim"))
    picked = retry_input(console, "\nProtect which? Numbers with spaces (1 3 5), a range (1-4), a for all, b to go back: ",
                         lambda entry: parse_selection(entry, len(repos)))
    if picked is None:
        return
    console.print()
    for index in picked:
        repo = repos[index]
        label = str(repo).replace(str(Path.home()), "~", 1)
        if is_protected(repo):
            console.print(Text(f"  already protected  {label}", style="dim"))
            continue
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                install_hook(repo)
        except (ToolError, OSError) as error:
            console.print(Text(f"  not protected      {label}: {error}", style=ACCENT))
            continue
        remember(repo)
        console.print(Text("  protected          ", style="bold green") + Text(label))
    console.print(Text("\nTo remove it from a project later: vapt hook uninstall <project folder>", style="dim"))
    pause(console)


def protect_all_pushes(console: Console) -> None:
    """Non-interactive version of protect_pushes: protects every repo found under
    the home folder with no per-repo picking, used for the first-install flow."""
    console.print(Text("Push protection", style="bold"))
    console.print(Text("Before each git push, checks the new commits for leaked secrets and, if dependencies "
                       "changed, for high/critical vulnerable packages. Findings block the push; if the check "
                       "can't run (for example Docker is off) it warns and lets the push through.", style="dim"))
    console.print(Text("\nLooking for Git projects in your home folder...", style="dim"))
    repos = find_repos(Path.home())
    if not repos:
        console.print(Text("No Git projects found. Clone a project first, then come back here.", style=ACCENT))
        pause(console)
        return
    to_protect = [repo for repo in repos if not is_protected(repo)]
    if not to_protect:
        console.print(Text(f"All {len(repos)} Git project(s) found are already protected.", style="dim"))
        pause(console)
        return
    console.print(Text(f"\nFound {len(repos)} Git project(s); {len(to_protect)} not yet protected:", style="dim"))
    for repo in to_protect:
        console.print(Text(f"  {str(repo).replace(str(Path.home()), '~', 1)}", style="dim"))
    console.print(Text("\nProtecting all of them now. Press Ctrl-C in the next 5 seconds to pick manually instead.",
                       style=ACCENT))
    try:
        time.sleep(5)
    except KeyboardInterrupt:
        console.print()
        protect_pushes(console)
        return
    console.print()
    for repo in to_protect:
        label = str(repo).replace(str(Path.home()), "~", 1)
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                install_hook(repo)
        except (ToolError, OSError) as error:
            console.print(Text(f"  not protected      {label}: {error}", style=ACCENT))
            continue
        remember(repo)
        console.print(Text("  protected          ", style="bold green") + Text(label))
    console.print(Text("\nProjects cloned later are not covered; use option 7 from the menu to add them.",
                       style="dim"))
    console.print(Text("To remove it from a project later: vapt hook uninstall <project folder>", style="dim"))
    pause(console)


def readiness_rows() -> tuple[list[tuple[str, bool, str]], bool]:
    rows = [(check["name"], check["ready"], check["detail"]) for check in diagnose("push")["checks"]]
    docker_running = False
    if shutil.which("docker"):
        docker_running = subprocess.run(["docker", "info"], capture_output=True).returncode == 0
        rows.append(("docker running", docker_running, "Docker is running." if docker_running else "Start Docker first."))
    else:
        native = [name for name, found in (("Nuclei", nuclei_binary()), ("ZAP", zap_binary())) if found]
        rows.append(("local attack testing", bool(native),
                    f"Available natively: {', '.join(native)}." if native else
                    "No Docker and no native Nuclei/ZAP found; install one to enable local attack testing."))
    return rows, docker_running


def check_ready(console: Console) -> None:
    rows, docker_running = readiness_rows()
    console.print()
    for name, ready, detail in rows:
        mark = Text("  OK    ", style="bold green") if ready else Text("  MISSING ", style=f"bold {ACCENT}")
        console.print(mark + Text(f"{name}: ", style="bold") + Text(detail))
    if docker_running:
        missing = missing_local_attack_images()
        if not missing:
            console.print(Text("Local attack testing images (Nuclei, ZAP) are already downloaded.", style="dim"))
        else:
            names = ", ".join(LOCAL_ATTACK_IMAGES[image] for image in missing)
            console.print(Text(f"\n{names} not downloaded yet; local attack testing would download "
                               "them on first use (a few hundred MB).", style=ACCENT))
            if ask(console, "Download now instead? (y/N): ").lower() == "y":
                for image in missing:
                    console.print(Text(f"\nPulling {image}...", style="dim"))
                    stream(["docker", "pull", image], lambda line: console.print(Text("  " + line, style="dim")))
    pause(console)


def report_problem(console: Console) -> None:
    console.print(Text("Report a problem", style="bold"))
    console.print(Text("Collects diagnostics only: versions, your setup and the last error. No findings, code or "
                       "secrets, and your username is hidden. You'll see everything before it's sent.", style="dim"))
    rows, _ = readiness_rows()
    protected = sum(is_protected(Path(entry)) for entry in load_recent())
    report = diagnostics(rows, protected)
    console.print()
    console.print(Text(report, style="dim"))
    what = ask(console, "\nWhat were you doing when it went wrong? (one line, Enter to skip): ")
    body = (f"## What happened\n{sanitize(what)}\n\n" if what else "") + report
    PRIVATE.mkdir(mode=0o700, exist_ok=True)
    saved = PRIVATE / ("problem-report-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S") + ".md")
    saved.write_text(body)
    console.print(Text("\nSaved a copy: ") + path_link(saved))
    if ask(console, "Open it as a GitHub issue for the maintainer? (Y/n): ").lower() in ("", "y", "yes"):
        title = "Pilot problem: " + (sanitize(what)[:80] if what else f"v{version('matt-vapt-kit')} on {platform.system()}")
        if webbrowser.open(issue_url(repo_slug(KIT), title, body)):
            console.print(Text("Your browser opened the issue. Check it and press Submit.", style="green"))
        else:
            console.print(Text("Couldn't open a browser; send the saved copy above in chat instead.", style=ACCENT))
    pause(console)


MENU = (
    ("Quick start", (
        ("0", "Full scan of a project", "every branch, staging check, all PDFs, one summary"),
    )),
    ("Scan", (
        ("1", "Scan a project", "secrets, dependencies, code rules, API auth"),
        ("2", "Latest results", "summary table and PDF report"),
        ("3", "Compare last two scans", "what is new and what got fixed"),
    )),
    ("Live checks", (
        ("4", "Quick staging check", "read-only headers, cookies, exposed files"),
        ("5", "Local attack testing", "Nuclei and ZAP against your localhost"),
    )),
    ("Setup", (
        ("6", "Check this computer", "Python, Git, Docker, scanner images"),
        ("7", "Protect git pushes", "block leaked secrets before each push"),
        ("8", "Report a problem", "send diagnostics to the maintainer"),
    )),
)


def ago(moment: datetime) -> str:
    seconds = (datetime.now(timezone.utc) - moment).total_seconds()
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60)):
        if seconds >= size:
            return f"{int(seconds // size)}{unit} ago"
    return "just now"


def status_line() -> Text:
    """One dim line of real state: the last scan and how many projects have push protection."""
    line = Text(style="dim")
    folder = latest_scan()
    if folder is None:
        line.append("No scans yet. Start with 1.")
    else:
        summary = json.loads((folder / "summary.json").read_text())
        name = summary.get("project", "last scan")
        when = ago(datetime.fromisoformat(summary["finished_at"])) if summary.get("finished_at") else "unfinished"
        attention = sum(row["status"] != "DONE" for row in summary.get("checks", []))
        line.append("Last scan        ")
        line.append(name, style="bold")
        line.append(f" · {when} · ")
        line.append(f"{attention} need attention" if attention else "all checks done",
                    style=ACCENT if attention else "green")
    protected = sum(is_protected(Path(entry)) for entry in load_recent())
    line.append("\nPush protection  ")
    line.append(f"on for {protected} recent project{'s' if protected != 1 else ''}" if protected
                else "off (choose 7 to turn it on)", style="green" if protected else ACCENT)
    return line


def menu_block(hints: bool = True) -> Table:
    grid = Table.grid(padding=(0, 2))
    grid.add_column(justify="right", no_wrap=True)
    grid.add_column(no_wrap=True)
    grid.add_column(style="dim", no_wrap=True)
    for index, (section, items) in enumerate(MENU):
        if index:
            grid.add_row("", "", "")
        grid.add_row("", Text(section.upper(), style="dim bold"), "")
        for key, label, hint in items:
            grid.add_row(Text(key, style="bold"), Text(label), hint if hints else "")
    grid.add_row("", "", "")
    grid.add_row(Text("q", style="bold"), Text("Quit"), "")
    return grid


MENU_MARGIN = 2


def print_menu(console: Console) -> int:
    """Draw the grouped menu left-aligned under the logo; returns the left margin used, for the prompt."""
    margin = MENU_MARGIN
    block = menu_block()
    if console.measure(block).maximum + margin > console.width:
        block = menu_block(hints=False)
    console.print(Padding(block, (0, 0, 0, margin)))
    console.print()
    console.print(Padding(status_line(), (0, 0, 0, margin)))
    return margin


def main() -> int:
    console = Console(highlight=False, no_color=bool(os.environ.get("NO_COLOR")))
    actions = {"0": full_scan, "1": run_scan, "2": show_latest, "3": show_compare,
               "4": run_staging_check, "5": run_local_attack, "6": check_ready, "7": protect_pushes,
               "8": report_problem}
    if "--protect" in sys.argv[1:] or "--protect-all" in sys.argv[1:]:
        console.clear()
        print_header(console)
        try:
            if "--protect-all" in sys.argv[1:]:
                protect_all_pushes(console)
            else:
                protect_pushes(console)
        except (KeyboardInterrupt, EOFError):
            console.print()
    try:
        update_notice = check_for_update()
    except Exception:
        update_notice = None
    while True:
        console.clear()
        print_header(console)
        if update_notice:
            console.print(Text(update_notice, style=ACCENT))
            console.print()
        margin = print_menu(console)
        try:
            choice = ask(console, "\n" + " " * margin + "Choose › ").lower()
            if choice in ("q", "quit", "exit"):
                return 0
            if choice in actions:
                actions[choice](console)
        except (KeyboardInterrupt, EOFError):
            console.print()
            return 0
        except Exception:
            record_error(f"menu option {choice}", traceback.format_exc())
            console.print(Text("\nSomething went wrong and was recorded. Choose 8 to report it.", style=ACCENT))
            pause(console)
