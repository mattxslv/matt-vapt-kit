"""Numbered terminal menu for the committed-code scan and its results."""
import contextlib
import getpass
import io
import json
import os
import re
import shutil
import subprocess
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

import yaml
from rich import box
from rich.console import Console
from rich.table import Table
from rich.text import Text

from .assessment import approval_template, assess
from .config import ConfigError, load_config
from .doctor import diagnose
from .hooks import install as install_hook
from .process import ToolError, git, stream
from .scan import path_link, print_header, scan

KIT = Path(__file__).resolve().parent.parent
PRIVATE = KIT / ".private"
PROJECTS = KIT / "projects"
RECENT_LIMIT = 8
WINDOWS = os.name == "nt"
SEARCH_DEPTH = 4
SKIP_DIRS = {"node_modules", "AppData", "Library", "snap", "venv", "site-packages", "vendor", "go", "Downloads"}


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
    name = repo.name.lower()
    matches = [config for config in PROJECTS.glob("*.vapt.yml") if config.name.removesuffix(".vapt.yml") in name]
    return max(matches, key=lambda config: len(config.name), default=None)


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
            console.print(Text(f"{error} (type b to go back to the menu)", style="yellow"))


def option(console: Console, key: str, label: str) -> None:
    line = Text()
    line.append(f"  {key:>2}  ", style="bold")
    line.append(label, style="default")
    console.print(line)


def choose_project(console: Console) -> Path | None:
    recent = load_recent()
    console.print(Text("Which project?", style="bold"))
    for number, entry in enumerate(recent, start=1):
        option(console, str(number), entry.replace(str(Path.home()), "~", 1))
    option(console, "n", "Type a new project folder path")
    option(console, "b", "Back")
    choice = ask(console, "\nChoose: ").lower()
    if choice.isdigit() and 1 <= int(choice) <= len(recent):
        return Path(recent[int(choice) - 1])
    if choice == "n":
        typed = ask(console, "Project folder (for example ~/DTAP): ")
        return Path(typed).expanduser() if typed else None
    return None


def run_scan(console: Console) -> None:
    repo = choose_project(console)
    if repo is None:
        return
    try:
        repo = Path(git(repo, "rev-parse", "--show-toplevel")).resolve()
    except ToolError:
        console.print(Text(f"\n{repo} is not a Git project folder.", style="yellow"))
        pause(console)
        return
    remember(repo)
    config = matching_config(repo)
    PRIVATE.mkdir(mode=0o700, exist_ok=True)
    output = PRIVATE / ("scan-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6])
    console.clear()
    try:
        scan(repo, config_path=config, output=output, console=console)
    except KeyboardInterrupt:
        console.print(Text("\nScan stopped.", style="yellow"))
    except ToolError as error:
        console.print(Text(f"\n{error}", style="yellow"))
    pause(console)


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
        console.print(Text("\nNeed at least two scans to compare. Run another scan first.", style="yellow"))
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

    section("New static-rule matches", diff["new_static"], "yellow")
    section("Resolved static-rule matches", diff["resolved_static"], "green")
    section("API routes newly missing authentication", diff["new_no_auth_routes"], "yellow")
    section("API routes that now have authentication", diff["resolved_no_auth_routes"], "green")
    if not any(diff.values()):
        console.print(Text("\nNo change in static matches or no-authentication routes between these two scans.", style="dim"))
    pause(console)


def show_latest(console: Console) -> None:
    folder = latest_scan()
    if folder is None:
        console.print(Text("\nNo scans yet. Choose 1 to run one.", style="yellow"))
        pause(console)
        return
    summary = json.loads((folder / "summary.json").read_text())
    table = Table(title="Latest scan", title_style="bold", header_style="bold",
                  box=box.ROUNDED, border_style="grey50", show_lines=True, padding=(0, 1))
    table.add_column("Check", ratio=2)
    table.add_column("Status", no_wrap=True)
    table.add_column("Detail", ratio=4, overflow="fold")
    for row in summary["checks"]:
        color = "green" if row["status"] == "DONE" else "yellow"
        label = row["check"].split("  ", 1)[-1]
        table.add_row(Text(label), Text(row["status"], style=f"bold {color}"), Text(row["detail"]))
    console.print()
    console.print(table)
    console.print(Text(f"Finished {summary.get('finished_at', 'unknown')}  |  commit {summary['revision'][:12]}", style="dim"))
    console.print(Text("Saved in ") + path_link(folder))
    console.print()
    option(console, "o", "Open this folder")
    option(console, "b", "Back")
    if ask(console, "\nChoose: ").lower() == "o":
        if WINDOWS:
            os.startfile(folder)
            return
        if not shutil.which("xdg-open"):
            console.print(Text("xdg-open is not available; open the folder above manually.", style="yellow"))
            pause(console)
            return
        subprocess.Popen(["xdg-open", str(folder)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


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


def staging_recap(result: dict) -> str:
    confirmed = sum(item["verification"] == "confirmed" for item in result["findings"])
    suspected = sum(item["verification"] == "suspected" for item in result["findings"])
    exposed = len(result.get("exposure", []))
    parts = []
    if confirmed:
        parts.append(f"{confirmed} confirmed header/cookie issues")
    if suspected:
        parts.append(f"{suspected} suspected header/cookie issues")
    if exposed:
        parts.append(f"{exposed} exposed files or endpoints")
    if result["errors"]:
        parts.append(f"{len(result['errors'])} requests that did not complete")
    if not parts:
        return "Nothing was flagged on the pages checked. This only covered headers, cookies and a short exposure list, not a full test."
    text = "Found " + (parts[0] if len(parts) == 1 else ", ".join(parts[:-1]) + " and " + parts[-1]) + "."
    if exposed:
        text += " Next, open assessment.json's exposure section and confirm each exposed path, then restrict or remove it."
    elif confirmed:
        text += " Next, fix the confirmed header/cookie issues; they were observed twice."
    elif suspected:
        text += " Next, review the suspected findings; they were only observed once."
    return text


def run_staging_check(console: Console) -> None:
    console.print(Text("Quick staging check", style="bold"))
    console.print(Text("Safe, read-only checks: security headers, cookies, and a short list of commonly "
                       "exposed files/endpoints (.env, .git/HEAD, debug endpoints, source maps).", style="dim"))
    console.print(Text("Login-protected sites (for example anything behind Google IAP) are not supported here.", style="dim"))
    config = retry_input(console, "\nStaging URL (or b to go back): ", staging_config)
    if config is None:
        return
    console.print(Text(f"\nThis will send a small number of HEAD/GET requests to {config['target']['url']}.", style="yellow"))
    if ask(console, "Do you have permission to test this site? (y/N): ").lower() != "y":
        console.print(Text("\nStopped. Get permission from the site owner first.", style="yellow"))
        pause(console)
        return
    approver = ask(console, f"Your name [{getpass.getuser()}]: ") or getpass.getuser()
    minutes_raw = ask(console, "Test window in minutes, 1-240 [60]: ") or "60"
    try:
        minutes = max(1, min(240, int(minutes_raw)))
    except ValueError:
        minutes = 60
    PRIVATE.mkdir(mode=0o700, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6]
    config_path = PRIVATE / f"quick-staging-{stamp}.vapt.yml"
    config_path.write_text(yaml.safe_dump(config, sort_keys=False))
    config_path.chmod(0o600)
    try:
        config = load_config(config_path)
    except ConfigError as error:
        console.print(Text(f"\n{error}", style="yellow"))
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
    output = PRIVATE / f"quick-staging-{stamp}"
    console.print(Text(f"\nChecking {config['target']['url']} for up to {minutes} minute(s)..."))
    try:
        path, code = assess(config, approval, output)
    except ToolError as error:
        console.print(Text(f"\n{error}", style="yellow"))
        pause(console)
        return
    result = json.loads(path.read_text())
    console.print(Text(f"\nStatus: {result['status']}", style="bold"))
    console.print(Text(f"Saved to {output}", style="dim"))
    console.print()
    console.print(Text("※ recap: ", style="bold dim") + Text(staging_recap(result), style="italic dim"))
    pause(console)


LOCAL_HOSTS = ("localhost", "127.0.0.1")
NUCLEI_TIMEOUT_SECONDS = 600
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
                       "or production.", style="yellow"))
    url = retry_input(console, "\nLocal port or URL [3000] (or b to go back): ", local_url)
    if url is None:
        return
    if ask(console, "This app is running locally and it's OK to attack-test it now? (y/N): ").lower() != "y":
        console.print(Text("\nStopped; nothing was run.", style="dim"))
        pause(console)
        return
    if not shutil.which("docker"):
        console.print(Text("\nDocker is required for local attack testing.", style="yellow"))
        pause(console)
        return
    available = available_memory_mb()
    if available is not None and available < LOW_MEMORY_MB:
        console.print(Text(f"\nOnly {available} MiB RAM is free; these scanners can make the machine "
                           "slow or unresponsive. Close other apps first.", style="yellow"))
        if ask(console, "Continue anyway? (y/N): ").lower() != "y":
            console.print(Text("\nStopped; nothing was run.", style="dim"))
            pause(console)
            return
    PRIVATE.mkdir(mode=0o700, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6]
    output = PRIVATE / f"attack-{stamp}"
    output.mkdir(mode=0o700)
    console.clear()
    print_header(console)
    target, network = container_target(url)
    console.print(Text(f"Target   {url}", style="dim"))
    if target != url:
        console.print(Text(f"Scanners reach it as {target} (Docker Desktop's name for this computer).", style="dim"))
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
    nuclei_name = f"mvk-nuclei-{stamp}"
    console.rule(Text("1 / 2  Nuclei known-issue scan", style="bold"), align="left", style="grey37")
    nuclei_log, code, nuclei_timed_out = stream([
        "docker", "run", "--rm", *network, "--name", nuclei_name,
        "--memory=1g", "--memory-swap=1g",
        "-v", f"{output}:/output",
        next(image for image in LOCAL_ATTACK_IMAGES if "nuclei" in image),
        "-u", target, "-severity", "low,medium,high,critical", "-c", "10", "-o", "/output/nuclei.txt",
    ], printer, timeout=NUCLEI_TIMEOUT_SECONDS, on_timeout=stop(nuclei_name))
    hits = len((output / "nuclei.txt").read_text().splitlines()) if (output / "nuclei.txt").is_file() else 0
    if nuclei_timed_out:
        summary.append(f"Nuclei: stopped after {NUCLEI_TIMEOUT_SECONDS // 60} minute(s); {hits} matched issue(s) so far.")
    else:
        summary.append(f"Nuclei: {hits} matched issue(s)." if code == 0 else "Nuclei: scan did not complete; see nuclei.txt.")
    console.print(Text(f"  {summary[-1]}", style="bold " + ("yellow" if hits or code else "green")))
    console.print()

    zap_name = f"mvk-zap-{stamp}"
    console.rule(Text("2 / 2  ZAP active scan", style="bold"), align="left", style="grey37")
    (output / "zap-rules.conf").write_text(ZAP_RULES)
    zap_log, code, zap_timed_out = stream([
        "docker", "run", "--rm", *network, "--name", zap_name,
        "--memory=2g", "--memory-swap=2g", "-e", "JAVA_OPTS=-Xmx1536m",
        "-v", f"{output}:/zap/wrk:rw",
        next(image for image in LOCAL_ATTACK_IMAGES if "zap" in image),
        "zap-full-scan.py", "-t", target, "-r", "zap-report.html", "-c", "zap-rules.conf", "-I", "-s",
    ], zap_printer, timeout=ZAP_TIMEOUT_SECONDS, on_timeout=stop(zap_name))
    alerts = zap_alert_count(zap_log)
    if zap_timed_out:
        summary.append(f"ZAP: stopped after {ZAP_TIMEOUT_SECONDS // 60} minute(s); partial results may be in zap-report.html.")
    else:
        summary.append(f"ZAP: {alerts} alert(s) raised." if (output / "zap-report.html").is_file() else "ZAP: scan did not complete.")
    console.print(Text(f"  {summary[-1]}", style="bold " + ("yellow" if alerts or zap_timed_out else "green")))

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
        console.print(Text("No Git projects found. Clone a project first, then come back here.", style="yellow"))
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
            console.print(Text(f"  not protected      {label}: {error}", style="yellow"))
            continue
        remember(repo)
        console.print(Text("  protected          ", style="bold green") + Text(label))
    console.print(Text("\nTo remove it from a project later: vapt hook uninstall <project folder>", style="dim"))
    pause(console)


def check_ready(console: Console) -> None:
    result = diagnose("push")
    rows = [(check["name"], check["ready"], check["detail"]) for check in result["checks"]]
    docker_running = False
    if shutil.which("docker"):
        docker_running = subprocess.run(["docker", "info"], capture_output=True).returncode == 0
        rows.append(("docker running", docker_running, "Docker is running." if docker_running else "Start Docker first."))
    console.print()
    for name, ready, detail in rows:
        mark = Text("  OK    ", style="bold green") if ready else Text("  MISSING ", style="bold yellow")
        console.print(mark + Text(f"{name}: ", style="bold") + Text(detail))
    console.print(Text("\nThe project's own pnpm version is checked during the scan.", style="dim"))
    if docker_running:
        missing = missing_local_attack_images()
        if not missing:
            console.print(Text("Local attack testing images (Nuclei, ZAP) are already downloaded.", style="dim"))
        else:
            names = ", ".join(LOCAL_ATTACK_IMAGES[image] for image in missing)
            console.print(Text(f"\n{names} not downloaded yet; local attack testing would download "
                               "them on first use (a few hundred MB).", style="yellow"))
            if ask(console, "Download now instead? (y/N): ").lower() == "y":
                for image in missing:
                    console.print(Text(f"\nPulling {image}...", style="dim"))
                    stream(["docker", "pull", image], lambda line: console.print(Text("  " + line, style="dim")))
    pause(console)


def main() -> int:
    console = Console(highlight=False, no_color=bool(os.environ.get("NO_COLOR")))
    actions = {"1": run_scan, "2": show_latest, "3": check_ready,
               "4": run_staging_check, "5": run_local_attack, "6": show_compare, "7": protect_pushes}
    if "--protect" in sys.argv[1:]:
        console.clear()
        print_header(console)
        try:
            protect_pushes(console)
        except (KeyboardInterrupt, EOFError):
            console.print()
    while True:
        console.clear()
        print_header(console)
        option(console, "1", "Scan a project for vulnerabilities")
        option(console, "2", "See the latest scan results")
        option(console, "3", "Check this computer is ready to scan")
        option(console, "4", "Quick staging check (paste a staging link)")
        option(console, "5", "Local attack testing (localhost only)")
        option(console, "6", "Compare the last two scans")
        option(console, "7", "Protect your git pushes (check for leaks before each push)")
        option(console, "q", "Quit")
        try:
            choice = ask(console, "\nChoose: ").lower()
            if choice in ("q", "quit", "exit"):
                return 0
            if choice in actions:
                actions[choice](console)
        except (KeyboardInterrupt, EOFError):
            console.print()
            return 0
