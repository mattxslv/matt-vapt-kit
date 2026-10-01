import subprocess
from pathlib import Path


class ToolError(RuntimeError):
    pass


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
