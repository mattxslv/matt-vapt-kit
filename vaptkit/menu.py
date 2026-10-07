"""Numbered terminal menu for the committed-code scan and its results."""
import json
import os
import shutil
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path

from rich import box
from rich.console import Console
from rich.table import Table
from rich.text import Text

from .doctor import diagnose
from .process import ToolError, git
from .scan import ACCENT, path_link, print_header, scan

KIT = Path(__file__).resolve().parent.parent
PRIVATE = KIT / ".private"
PROJECTS = KIT / "projects"
RECENT_LIMIT = 8


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
    return console.input(Text(prompt, style=f"bold {ACCENT}")).strip()


def pause(console: Console) -> None:
    ask(console, "\nPress Enter to go back to the menu...")


def option(console: Console, key: str, label: str) -> None:
    console.print(Text(f"  {key:>2}  ", style=f"bold {ACCENT}") + Text(label))


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


def show_latest(console: Console) -> None:
    folder = latest_scan()
    if folder is None:
        console.print(Text("\nNo scans yet. Choose 1 to run one.", style="yellow"))
        pause(console)
        return
    summary = json.loads((folder / "summary.json").read_text())
    table = Table(title="Latest scan", title_style="bold", header_style="bold",
                  box=box.ROUNDED, border_style=ACCENT, show_lines=True, padding=(0, 1))
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
        if not shutil.which("xdg-open"):
            console.print(Text("xdg-open is not available; open the folder above manually.", style="yellow"))
            pause(console)
            return
        subprocess.Popen(["xdg-open", str(folder)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def check_ready(console: Console) -> None:
    result = diagnose("push")
    rows = [(check["name"], check["ready"], check["detail"]) for check in result["checks"]]
    if shutil.which("docker"):
        running = subprocess.run(["docker", "info"], capture_output=True).returncode == 0
        rows.append(("docker running", running, "Docker is running." if running else "Start Docker first."))
    console.print()
    for name, ready, detail in rows:
        mark = Text("  OK    ", style="bold green") if ready else Text("  MISSING ", style="bold yellow")
        console.print(mark + Text(f"{name}: ", style="bold") + Text(detail))
    console.print(Text("\nThe project's own pnpm version is checked during the scan.", style="dim"))
    pause(console)


def main() -> int:
    console = Console(highlight=False, no_color=bool(os.environ.get("NO_COLOR")))
    actions = {"1": run_scan, "2": show_latest, "3": check_ready}
    while True:
        console.clear()
        print_header(console)
        option(console, "1", "Scan a project for vulnerabilities")
        option(console, "2", "See the latest scan results")
        option(console, "3", "Check this computer is ready to scan")
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
