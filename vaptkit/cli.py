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
    combined = commands.add_parser("scan", help="Run all supported committed-code checks with readable progress")
    combined.add_argument("repo", type=Path, nargs="?", default=Path.cwd())
    combined.add_argument("--config", type=Path, help="Optional project policy for offline API authentication review")
    combined.add_argument("--output", type=Path, help="New private output directory (default: .private/scan-*)")
    combined.add_argument("--plain", action="store_true", help="Disable color and loading animation")
    combined.add_argument("--pdf", action="store_true", help="Also write report.html and report.pdf with the evidence")
    combined.add_argument("--revision", default="HEAD",
                          help="Branch or commit to scan without checking it out, e.g. origin/main (default: HEAD)")
    validate = commands.add_parser("validate", help="Validate staging config offline")
    validate.add_argument("config", type=Path)
    doctor = commands.add_parser("doctor", help="Check core tools or task-specific prerequisites without scans")
    from .doctor import PROFILES
    doctor.add_argument("--for", dest="profile", choices=PROFILES, help="Check only prerequisites for this task")
    doctor.add_argument("--config", type=Path, help="Role project configuration for gateway prerequisite checks")
    checks = commands.add_parser("check", help="Check a committed Git tree")
    checks.add_argument("repo", type=Path)
    checks.add_argument("--revision", default="HEAD")
    checks.add_argument("--static", action="store_true")
    hooks = commands.add_parser("hook", help="Install or remove local pre-push protection")
    hooks.add_argument("action", choices=["install", "uninstall"])
    hooks.add_argument("repo", type=Path)
    routes = commands.add_parser("review-routes", help="Offline source review of API route authentication")
    routes.add_argument("config", type=Path)
    routes.add_argument("repo", type=Path)
    routes.add_argument("--revision", default="HEAD")
    routes.add_argument("--output", type=Path, required=True, help="New private JSON file")
    armor = commands.add_parser("review-armor", help="Read-only Cloud Armor metadata review for a declared staging service")
    armor.add_argument("config", type=Path)
    armor.add_argument("--gcp-project", required=True)
    armor.add_argument("--service", required=True)
    armor.add_argument("--region", required=True)
    armor.add_argument("--acknowledge-scope", action="store_true")
    armor.add_argument("--output", type=Path, required=True, help="New sanitized private JSON file")
    scope = commands.add_parser("scope-template", help="Print an unapproved HEAD-only scope template")
    scope.add_argument("config", type=Path)
    scope.add_argument("--roles", action="store_true", help="Print an unapproved role-login and GET matrix scope")
    scope.add_argument("--ownership", action="store_true", help="Print an unapproved two-account ownership-check scope")
    roles = commands.add_parser("roles", help="Test an approved read-only role matrix with isolated DTAP logins")
    roles.add_argument("config", type=Path)
    roles.add_argument("--approval", type=Path, required=True)
    roles.add_argument("--output", type=Path, required=True)
    roles.add_argument("--acknowledge-scope", action="store_true")
    roles.add_argument("--prompt-passwords", action="store_true",
                       help="Prompt with hidden input for missing QA passwords; never saved to environment or files")
    ownership = commands.add_parser("ownership", help="Test configured two-account ownership checks with isolated DTAP logins")
    ownership.add_argument("config", type=Path)
    ownership.add_argument("--approval", type=Path, required=True)
    ownership.add_argument("--output", type=Path, required=True)
    ownership.add_argument("--acknowledge-scope", action="store_true")
    ownership.add_argument("--prompt-passwords", action="store_true",
                           help="Prompt with hidden input for missing QA passwords; never saved to environment or files")
    scan = commands.add_parser("run", help="Run approved header checks and optional bounded public exposure checks")
    scan.add_argument("config", type=Path)
    scan.add_argument("--approval", type=Path, required=True)
    scan.add_argument("--output", type=Path, required=True)
    scan.add_argument("--acknowledge-scope", action="store_true")
    scan.add_argument("--baseline", type=Path, help="Earlier assessment.json to retest finding by finding")
    report = commands.add_parser("report", help="Render reviewed observations as HTML, PDF and PNG")
    report.add_argument("input", type=Path)
    report.add_argument("--output", type=Path, required=True)
    report.add_argument("--reviewed", action="store_true")
    report.add_argument("--html-only", action="store_true")
    report.add_argument("--tlp", default="AMBER+STRICT",
                        choices=["RED", "AMBER+STRICT", "AMBER", "GREEN", "CLEAR"])
    report.add_argument("--prepared-by", default="", help="Name shown on the sign-off block")
    report.add_argument("--agency", default="", help="Agency/Office shown in the report details")
    report.add_argument("--source-review", type=Path, help="Merge suspected findings from vapt review-routes")
    report.add_argument("--cloud-review", type=Path, help="Include sanitized read-only Cloud Armor review")
    args = parser.parse_args(argv)

    if args.command == "doctor" and args.profile is None and args.config is None:
        tools = {tool: shutil.which(tool) is not None for tool in CORE_TOOLS}
        print(json.dumps({"core_tools": tools}, indent=2))
        return 0 if all(tools.values()) else 1

    try:
        if args.command == "scan":
            from .scan import scan
            return scan(args.repo, config_path=args.config, output=args.output, plain=args.plain, pdf=args.pdf,
                        revision=args.revision, branch=None if args.revision == "HEAD" else args.revision)
        if args.command == "doctor":
            from .doctor import diagnose
            if args.config is not None and args.profile != "roles":
                raise ToolError("doctor --config is supported only with --for roles.")
            config = load_config(args.config) if args.config else None
            result = diagnose(args.profile, config)
            print(json.dumps(result, indent=2))
            return 0 if result["ready"] else 1
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
                source_review=args.source_review, cloud_review=args.cloud_review,
            )
            print(f"Report written to {path}")
            if not args.html_only:
                print(f"PDF written to {path.with_name('report.pdf')}")
            return 0
        config = load_config(args.config)
        if args.command == "review-armor":
            from .armor import collect
            from .assessment import write_private
            if not args.acknowledge_scope:
                raise ToolError("Acknowledge owner permission for read-only metadata in this exact staging project and service.")
            if args.output.exists() or not args.output.parent.is_dir():
                raise ToolError("Cloud review needs a new JSON file inside an existing private directory.")
            result = collect(config, args.gcp_project, args.service, args.region)
            write_private(args.output, json.dumps(result, indent=2))
            print(f"Cloud review written to {args.output}: {len(result['backends'])} linked backends, "
                  f"{len(result['findings'])} configuration observations, {len(result['gaps'])} coverage gaps.")
            print("Metadata only. Application XSS and runtime Cloud Armor enforcement were not tested.")
            return 1 if result["status"] == "incomplete" else 0
        if args.command == "review-routes":
            from .assessment import write_private
            from .routes import review
            if args.output.exists():
                raise ToolError("Output file already exists; choose a new path.")
            result = review(args.repo, config, args.revision)
            write_private(args.output, json.dumps(result, indent=2))
            summary = result["summary"]
            print(f"Reviewed {summary['handlers']} handlers in {summary['route_files']} route files at {result['revision'][:12]}.")
            for item in result["findings"]:
                print(f"  [{item['severity'].upper():6}] {item['path']}  {item['title']}")
            print(f"Route review written to {args.output} ({len(result['findings'])} suspected).")
            return 0
        if args.command == "scope-template":
            from .assessment import approval_template
            from .roles import template as role_template
            from .ownership import template as ownership_template
            if args.roles:
                print(json.dumps(role_template(config), indent=2))
            elif args.ownership:
                print(json.dumps(ownership_template(config), indent=2))
            else:
                print(json.dumps(approval_template(config), indent=2))
            return 0
        if args.command == "roles":
            from .assessment import load_json
            from .roles import run
            if not args.acknowledge_scope:
                raise ToolError("Pass --acknowledge-scope only with explicit owner approval for role login and GET checks.")
            path, code = run(config, load_json(args.approval), args.output,
                             prompt_passwords=args.prompt_passwords)
            print(f"Role assessment written to {path}; " + ("incomplete." if code else "scoped matrix completed."))
            print_assessment_summary(path)
            return code
        if args.command == "ownership":
            from .assessment import load_json
            from .ownership import run as run_ownership
            if not args.acknowledge_scope:
                raise ToolError("Pass --acknowledge-scope only with explicit owner approval for ownership checks.")
            path, code = run_ownership(config, load_json(args.approval), args.output,
                                       prompt_passwords=args.prompt_passwords)
            print(f"Ownership assessment written to {path}; " + ("incomplete." if code else "no coverage gaps."))
            result = json.loads(path.read_text())
            for item in result["findings"]:
                print(f"  [{item['severity'].upper():6}] {item['verification']:9} {item['path']}  {item['title']}")
            if not result["findings"]:
                print("  No ownership findings.")
            return code
        if args.command == "run":
            from .assessment import assess, load_json
            if not args.acknowledge_scope:
                raise ToolError("Pass --acknowledge-scope only with the authorized owner's approval.")
            baseline = load_json(args.baseline) if args.baseline else None
            path, code = assess(config, load_json(args.approval), args.output, baseline)
            print(f"Assessment record written to {path}; " + ("incomplete." if code else "scoped checks completed."))
            print_assessment_summary(path)
            return code
    except ConfigError as error:
        print(f"Configuration error: {error}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\nCancelled by the operator. No remaining checks will be started.", file=sys.stderr)
        return 130
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


def print_assessment_summary(path: Path) -> None:
    from .assessment import load_json
    from .report import validate_result
    from .roles import role_outcome
    result = load_json(path)
    validate_result(result)
    findings = result["findings"]
    counts = {state: sum(item["verification"] == state for item in findings)
              for state in ("confirmed", "suspected", "observation")}
    print(f"Findings: {counts['confirmed']} confirmed, {counts['suspected']} suspected, "
          f"{counts['observation']} observations. Errors: {len(result['errors'])}.")
    if result["profile"] == "dtap-role-matrix":
        records = result.get("role_observations", [])
        controls = {item["path"] for item in records if role_outcome(item, set()) == "allowed"}
        outcomes = [role_outcome(item, controls) for item in records]
        expected = len(result.get("role_accounts", [])) * len(result["approved_paths"])
        tested = sum(outcome in ("allowed", "denied", "confirmed") for outcome in outcomes)
        print(f"Role cells: {tested}/{expected} tested, {outcomes.count('blocked')} blocked, "
              f"{outcomes.count('inconclusive')} inconclusive, {max(0, expected - len(records))} not run.")
        cleanup = result.get("role_cleanup", [])
        acknowledged = sum(item["status"] == "acknowledged" for item in cleanup)
        unconfirmed = sum(item["status"] == "unconfirmed" for item in cleanup)
        print(f"Sign-out: {acknowledged} acknowledged, {unconfirmed} unconfirmed. "
              "Acknowledgement does not prove revocation.")
        if unconfirmed:
            print("Manual session cleanup may be required; review the assessment record.")
        print("Ownership, workflows and live XSS: not tested.")
    else:
        successful = sum(200 <= item["status"] < 300 for item in result["observations"])
        print(f"Header paths: {successful}/{len(result['approved_paths'])} successful responses. "
              "Non-2xx or missing responses are coverage gaps.")
        print(f"Public data-exposure coverage: {result['coverage']['data_exposure']}. "
              f"Unauthorized-access coverage: {result['coverage']['unauthorized_access']}.")
    print("HTML/PDF report: not generated. Review this JSON, then use vapt report.")
    print("Zero findings is not a security guarantee; blocked and inconclusive checks are not passes.")
