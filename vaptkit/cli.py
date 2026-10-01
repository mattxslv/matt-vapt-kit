import argparse
import json
import shutil
import sys
from importlib.metadata import version
from pathlib import Path

from .config import ConfigError, load_config
from .process import ToolError

CORE_TOOLS = ("curl", "dig", "ffuf", "git", "nmap", "whatweb")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="vapt",
        description="Staging-first push checks, approved header observations and private reports.",
    )
    parser.add_argument("--version", action="version", version=version("matt-vapt-kit"))
    commands = parser.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate", help="Validate staging config offline")
    validate.add_argument("config", type=Path)
    commands.add_parser("doctor", help="Check installed core tools without running scans")
    checks = commands.add_parser("check", help="Check a committed Git tree")
    checks.add_argument("repo", type=Path)
    checks.add_argument("--revision", default="HEAD")
    checks.add_argument("--static", action="store_true")
    hooks = commands.add_parser("hook", help="Install or remove local pre-push protection")
    hooks.add_argument("action", choices=["install", "uninstall"])
    hooks.add_argument("repo", type=Path)
    scope = commands.add_parser("scope-template", help="Print an unapproved HEAD-only scope template")
    scope.add_argument("config", type=Path)
    scan = commands.add_parser("run", help="Make approved HEAD requests; optional configured IAP login")
    scan.add_argument("config", type=Path)
    scan.add_argument("--approval", type=Path, required=True)
    scan.add_argument("--output", type=Path, required=True)
    scan.add_argument("--acknowledge-scope", action="store_true")
    report = commands.add_parser("report", help="Render reviewed observations as HTML, PDF and PNG")
    report.add_argument("input", type=Path)
    report.add_argument("--output", type=Path, required=True)
    report.add_argument("--reviewed", action="store_true")
    report.add_argument("--html-only", action="store_true")
    report.add_argument("--tlp", default="AMBER+STRICT",
                        choices=["RED", "AMBER+STRICT", "AMBER", "GREEN", "CLEAR"])
    report.add_argument("--prepared-by", default="", help="Name shown on the sign-off block")
    report.add_argument("--agency", default="", help="Agency/Office shown in the report details")
    args = parser.parse_args(argv)

    if args.command == "doctor":
        tools = {tool: shutil.which(tool) is not None for tool in CORE_TOOLS}
        print(json.dumps({"core_tools": tools}, indent=2))
        return 0 if all(tools.values()) else 1

    try:
        if args.command == "check":
            from .checks import check
            check(args.repo, args.revision, static=args.static)
            return 0
        if args.command == "hook":
            from .hooks import install, uninstall
            (install if args.action == "install" else uninstall)(args.repo)
            return 0
        if args.command == "report":
            from .report import generate
            path = generate(
                args.input, args.output, reviewed=args.reviewed, html_only=args.html_only,
                tlp=args.tlp, prepared_by=args.prepared_by, agency=args.agency,
            )
            print(f"Report written to {path}")
            return 0
        config = load_config(args.config)
        if args.command == "scope-template":
            from .assessment import approval_template
            print(json.dumps(approval_template(config), indent=2))
            return 0
        if args.command == "run":
            from .assessment import assess, load_json
            if not args.acknowledge_scope:
                raise ToolError("Pass --acknowledge-scope only with the authorized owner's approval.")
            path, code = assess(config, load_json(args.approval), args.output)
            print(f"Assessment record written to {path}; " + ("incomplete." if code else "scoped checks completed."))
            return code
    except ConfigError as error:
        print(f"Configuration error: {error}", file=sys.stderr)
        return 2
    except ToolError as error:
        print(f"Operation failed: {error}", file=sys.stderr)
        return 2
    except OSError:
        print("Operation failed: local file or executable access error.", file=sys.stderr)
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
