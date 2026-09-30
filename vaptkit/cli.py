import argparse
import json
import shutil
import sys
from importlib.metadata import version
from pathlib import Path

from .config import ConfigError, load_config

CORE_TOOLS = ("curl", "dig", "ffuf", "git", "nmap", "whatweb")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="vapt",
        description="Matt VAPT Kit foundation. No commands contact assessment targets.",
    )
    parser.add_argument("--version", action="version", version=version("matt-vapt-kit"))
    commands = parser.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate", help="Validate staging config offline")
    validate.add_argument("config", type=Path)
    commands.add_parser("doctor", help="Check installed core tools without running scans")
    args = parser.parse_args(argv)

    if args.command == "doctor":
        tools = {tool: shutil.which(tool) is not None for tool in CORE_TOOLS}
        print(json.dumps({"core_tools": tools}, indent=2))
        return 0 if all(tools.values()) else 1

    try:
        config = load_config(args.config)
    except ConfigError as error:
        print(f"Configuration error: {error}", file=sys.stderr)
        return 2
    print(json.dumps({
        "project": config["project"],
        "configuration": "valid",
        "environment": config["target"]["environment"],
        "target_verification": config["target"]["verification"],
        "scan_authorized": False,
        "notice": "Offline validation only; no target contacted or credentials loaded.",
    }, indent=2))
    return 0
