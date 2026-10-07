import re
import subprocess
from pathlib import Path


class ToolError(RuntimeError):
    pass


def stream(command: list[str], printer, *, cwd: Path | None = None) -> tuple[str, int]:
    """Run a command, printing each output line via printer(line), and return (combined_text, exit_code)."""
    lines = []
    try:
        with subprocess.Popen(command, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              text=True, errors="replace") as process:
            for line in process.stdout:
                clean = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", line.rstrip())
                clean = "".join(char for char in clean if char == "\t" or char.isprintable())
                printer(clean)
                lines.append(clean)
            code = process.wait()
    except OSError:
        raise ToolError(f"Cannot start {command[0]}; install it before continuing.") from None
    return "\n".join(lines), code


def git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, check=False
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
