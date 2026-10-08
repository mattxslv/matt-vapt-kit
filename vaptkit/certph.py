"""Export a scan's findings as a remediation-ticket table, one row per finding.

Field names and layout are a best-effort mapping to the kind of table CERT-PH engagements and
DICT DC 003 s.2020 remediation reports commonly ask for (finding, OWASP category, severity,
affected component, description, recommendation, status). This kit has not seen an actual
CERT-PH template; confirm the exact fields and wording your ticket or report requires before
pasting this in, and adjust the headings below to match.
"""
import json
from datetime import date
from pathlib import Path

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
OWASP_LABEL = {
    "A01": "A01: Broken Access Control", "A02": "A02: Security Misconfiguration",
    "A03": "A03: Software and Data Integrity Failures", "A04": "A04: Insecure Design",
    "A05": "A05: Security Logging and Monitoring Failures", "A06": "A06: Vulnerable and Outdated Components",
    "A07": "A07: Identification and Authentication Failures", "A08": "A08: Software and Data Integrity Failures",
    "A09": "A09: Security Logging and Monitoring Failures", "A10": "A10: Server-Side Request Forgery",
}


def read(folder: Path, name: str) -> dict:
    path = folder / name
    return json.loads(path.read_text()) if path.is_file() else {}


def route_tickets(folder: Path) -> list[dict]:
    findings = read(folder, "route-review.json").get("findings", [])
    return [{
        "title": item["title"], "severity": item["severity"], "status": item["verification"],
        "owasp": item.get("owasp", "A01"), "component": f"{item.get('method', '')} {item['path']}".strip(),
        "description": item["impact"], "recommendation": item["remediation"],
    } for item in findings]


def static_tickets(folder: Path) -> list[dict]:
    messages = {}
    rules_dir = Path(__file__).parent / "rules"
    if rules_dir.is_dir():
        import yaml
        for path in rules_dir.glob("*.yml"):
            for rule in yaml.safe_load(path.read_text()).get("rules", []):
                messages[f"rules.{rule['id']}"] = rule["message"]
    grouped = {}
    for item in read(folder, "static-findings.json").get("findings", []):
        if item.get("runtime", True):
            grouped.setdefault(item["rule"], []).append(item)
    return [{
        "title": messages.get(rule, rule), "severity": "medium", "status": "suspected", "owasp": "A05",
        "component": f"{len(items)} location{'s' if len(items) != 1 else ''}, e.g. {items[0]['path']}:{items[0]['line']}",
        "description": f"Pattern match for {rule} in committed code reachable by the running application.",
        "recommendation": "Review each location and fix or justify it.",
    } for rule, items in grouped.items()]


def dependency_tickets(folder: Path) -> list[dict]:
    report = read(folder, "dependency-audit.json")
    grouped = {}
    for item in report.get("top", []):
        if item.get("scope") not in ("dev", "unused") and item["severity"] in ("critical", "high"):
            grouped.setdefault((item["package"], item["version"]), []).append(item["id"])
    return [{
        "title": f"Known vulnerabilities in {package} {version}", "severity": "high", "status": "confirmed",
        "owasp": "A06", "component": f"{package} {version}",
        "description": f"{len(ids)} high/critical advisor{'ies' if len(ids) != 1 else 'y'}: {', '.join(ids[:5])}"
                      + (f" and {len(ids) - 5} more" if len(ids) > 5 else "."),
        "recommendation": "Upgrade the package to a patched version.",
    } for (package, version), ids in grouped.items()]


def secret_tickets(folder: Path) -> list[dict]:
    findings = [item for item in read(folder, "secret-findings.json").get("findings", []) if not item["placeholder"]]
    return [{
        "title": f"Possible secret in Git history ({item['rule']})", "severity": "high", "status": "suspected",
        "owasp": "A02", "component": f"{item['file']}:{item['line']} (commit {item['commit'][:8]})",
        "description": "A commit matching a secret-detection rule was found in the repository's history. "
                      "The value itself is withheld.",
        "recommendation": "Confirm whether the value is real. If so, rotate it immediately; removing it from "
                          "the latest commit does not remove it from history.",
    } for item in findings]


def collect_tickets(folder: Path) -> list[dict]:
    tickets = route_tickets(folder) + static_tickets(folder) + dependency_tickets(folder) + secret_tickets(folder)
    return sorted(tickets, key=lambda item: SEVERITY_ORDER.get(item["severity"], 9))


def render_markdown(folder: Path, *, ticket_prefix: str = "MVK") -> str:
    summary = read(folder, "summary.json")
    project = summary.get("project", folder.name)
    revision = summary.get("revision", "")[:12]
    branch = summary.get("branch")
    tickets = collect_tickets(folder)
    lines = [
        f"# Remediation tickets · {project}" + (f" ({branch})" if branch else ""),
        "",
        f"Generated {date.today().isoformat()} from commit `{revision}`. {len(tickets)} finding(s), most severe first.",
        "Severity and status come from this kit's own checks: `confirmed` was independently observed twice (or, for "
        "dependencies, is a known advisory against the exact pinned version); `suspected` needs a person to confirm "
        "it before treating it as a real vulnerability. Field names below are a best-effort match to a typical "
        "remediation-ticket table; confirm against your actual CERT-PH / DC 003 s.2020 template before submitting.",
        "",
        "| # | Finding | OWASP | Severity | Status | Affected | Description | Recommendation |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for index, ticket in enumerate(tickets, 1):
        row = [
            f"{ticket_prefix}-{index:03d}", ticket["title"], OWASP_LABEL.get(ticket["owasp"], ticket["owasp"]),
            ticket["severity"].capitalize(), ticket["status"].capitalize(), ticket["component"],
            ticket["description"], ticket["recommendation"],
        ]
        lines.append("| " + " | ".join(cell.replace("|", "\\|").replace("\n", " ") for cell in row) + " |")
    if not tickets:
        lines.append("| - | No findings to export. | - | - | - | - | - | - |")
    return "\n".join(lines) + "\n"
