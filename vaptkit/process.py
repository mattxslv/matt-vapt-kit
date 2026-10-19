import os
import re
import subprocess
import sys
import threading
from pathlib import Path


class ToolError(RuntimeError):
    pass


DOCKER_START_TIMEOUT_SECONDS = 90
WINDOWS_DOCKER_DESKTOP_PATHS = (
    r"C:\Program Files\Docker\Docker\Docker Desktop.exe",
    r"C:\ProgramData\DockerDesktop\Docker Desktop.exe",
)


def docker_running() -> bool:
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=10).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def launch_docker() -> bool:
    """Best-effort, silent attempt to start Docker Desktop/Engine. True only if a launch was
    actually attempted (not that it necessarily finished starting - caller still has to wait)."""
    try:
        if os.name == "nt":
            path = os.environ.get("DOCKER_DESKTOP_PATH") or next(
                (path for path in WINDOWS_DOCKER_DESKTOP_PATHS if os.path.isfile(path)), None)
            if not path:
                return False
            subprocess.Popen([path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        if sys.platform == "darwin":
            return subprocess.run(["open", "-a", "Docker"], capture_output=True).returncode == 0
        # Linux: only a non-interactive sudo attempt - never prompt for a password, that would
        # hang a flow that's supposed to be hands-off. Most desktop Docker installs enable the
        # service already, so this mainly covers "installed but not yet started this boot".
        return subprocess.run(["sudo", "-n", "systemctl", "start", "docker"],
                              capture_output=True, timeout=10).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def stream(command: list[str], printer, *, cwd: Path | None = None,
           timeout: float | None = None, on_timeout=None) -> tuple[str, int, bool]:
    """Run a command, printing each output line via printer(line).

    Returns (combined_text, exit_code, timed_out). If timeout elapses, on_timeout()
    is called (for example to stop a named Docker container) and the process is
    killed; exit_code reflects the killed process, not a clean finish.
    """
    lines = []
    try:
        process = subprocess.Popen(command, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   text=True, encoding="utf-8", errors="replace")
    except OSError:
        raise ToolError(f"Cannot start {command[0]}; install it before continuing.") from None

    def reader():
        for line in process.stdout:
            clean = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", line.rstrip())
            clean = "".join(char for char in clean if char == "\t" or char.isprintable())
            printer(clean)
            lines.append(clean)

    reading = threading.Thread(target=reader, daemon=True)
    reading.start()
    reading.join(timeout)
    timed_out = reading.is_alive()
    if timed_out:
        if on_timeout:
            on_timeout()
        process.kill()
        reading.join(5)
    code = process.wait()
    process.stdout.close()
    return "\n".join(lines), code, timed_out


def git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True,
        encoding="utf-8", errors="replace", check=False
    )
    if result.returncode:
        raise ToolError("Git operation failed; check repository access and configuration.")
    return result.stdout.strip()


def run(command: list[str], *, cwd: Path | None = None, env=None) -> None:
    try:
        result = subprocess.run(command, cwd=cwd, env=env, check=False)
    except OSError:
        raise ToolError(f"Cannot start {command[0]}; install it before continuing.") from None
    if result.returncode:
        raise ToolError(f"{command[0]} failed (exit {result.returncode}); operation blocked.")
