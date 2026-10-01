"""Read-only Cloud Armor configuration review. No application requests or CEL evaluation."""
import ast
import json
import re
import subprocess
from datetime import datetime, timezone
from importlib.resources import files

from jsonschema import Draft202012Validator

from .assessment import reject_constant, unique_object
from .process import ToolError

LIMIT = 100
NAME = r"[a-z][a-z0-9-]{0,62}"
PROJECT = r"[a-z][a-z0-9-]{4,28}[a-z0-9]"
NOTE = (
    "Read-only metadata for an operator-declared Cloud Run service. Backend associations are not proof "
    "that the assessment URL routes through them. DNS, URL maps, forwarding rules, request blocking, "
    "WAF signature effectiveness and application XSS/SQL injection were not tested. Arbitrary CEL, "
    "URL-mask NEGs, edge policies and hierarchical policies require separate review. IAP and Cloud Armor "
    "are distinct controls. A configured WAF reference is not proof of protection."
)


def cloud_json(args: list[str], *, inventory=False):
    try:
        result = subprocess.run(["gcloud", *args, "--quiet"], capture_output=True, timeout=45)
    except (OSError, subprocess.TimeoutExpired):
        raise ToolError("Cloud metadata collection failed or timed out; raw details withheld.") from None
    if result.returncode:
        raise ToolError("Cloud metadata collection was denied or failed; no passing review produced.")
    if len(result.stdout) > 4_000_000:
        raise ToolError("Cloud metadata exceeds the review size limit; narrow the project inventory.")
    try:
        value = json.loads(result.stdout, object_pairs_hook=unique_object, parse_constant=reject_constant)
    except (ValueError, RecursionError):
        raise ToolError("Cloud metadata was invalid; raw contents withheld.") from None
    if inventory and (not isinstance(value, list) or len(value) > LIMIT):
        raise ToolError("Cloud inventory exceeds the 100-resource limit or is invalid; review not completed.")
    if not inventory and not isinstance(value, dict):
        raise ToolError("Cloud service metadata was invalid; raw contents withheld.")
    return value


def collect(config: dict, project: str, service: str, region: str) -> dict:
    if (not re.fullmatch(PROJECT, project) or not re.fullmatch(NAME, service)
            or not re.fullmatch(r"[a-z]+-[a-z]+[0-9]+", region)):
        raise ToolError("Cloud project, service and region must be explicit resource identifiers.")
    started = datetime.now(timezone.utc).isoformat()
    run = cloud_json([
        "run", "services", "describe", service, "--project=" + project, "--region=" + region,
        "--format=json(metadata.name,metadata.annotations,status.url)",
    ])
    inventories = []
    for resource, fields in (
        ("network-endpoint-groups", "name,selfLink,region,networkEndpointType,cloudRun"),
        ("backend-services", "name,selfLink,backends,securityPolicy,edgeSecurityPolicy,logConfig"),
        ("security-policies", "name,selfLink,type,rules"),
    ):
        inventories.append(cloud_json(
            ["compute", resource, "list", "--project=" + project, "--limit=101", "--format=json(" + fields + ")"],
            inventory=True,
        ))
    return review(config, project, service, region, run, *inventories, started=started)


def resource_path(value, project: str, kind: str) -> str | None:
    if not isinstance(value, str):
        return None
    match = re.fullmatch(
        rf"https://(?:www\.googleapis\.com|compute\.googleapis\.com)/compute/v1/"
        rf"(projects/{re.escape(project)}/(?:global|regions/{NAME})/{kind}/{NAME})", value,
    )
    return match[1] if match else None


def finding(title: str, evidence: str, impact: str, remediation: str) -> dict:
    return {"title": title, "severity": "low", "verification": "observation",
            "category": "configuration", "owasp": "A02", "path": "/",
            "evidence": evidence, "impact": impact, "remediation": remediation}


def waf_family(expression: str) -> str | None:
    if len(expression) > 4096:
        return None
    try:
        node = ast.parse(expression.strip(), mode="eval").body
        if (not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name)
                or node.func.id not in ("evaluatePreconfiguredWaf", "evaluatePreconfiguredExpr")
                or node.keywords or not 1 <= len(node.args) <= 2):
            return None
        name = ast.literal_eval(node.args[0])
        if len(node.args) == 2 and not isinstance(ast.literal_eval(node.args[1]), dict):
            return None
    except (SyntaxError, ValueError, TypeError, RecursionError):
        return None
    match = re.fullmatch(r"(xss|sqli)-[a-zA-Z0-9-]+", name) if isinstance(name, str) else None
    return match[1] if match else None


def review(config: dict, project: str, service: str, region: str, run: dict,
           negs: list, backends: list, policies: list, *, started: str) -> dict:
    if (not isinstance(run.get("metadata"), dict) or run["metadata"].get("name") != service
            or any(not isinstance(items, list) or len(items) > LIMIT
                   or any(not isinstance(item, dict) for item in items) for items in (negs, backends, policies))):
        raise ToolError("Cloud inventory does not match the requested service or supported shape.")
    annotations = run["metadata"].get("annotations", {})
    if not isinstance(annotations, dict):
        raise ToolError("Cloud service annotations have an unsupported shape.")
    gaps, findings, rows, linked = [], [], [], set()
    for neg in negs:
        if neg.get("networkEndpointType") != "SERVERLESS":
            continue
        reference = resource_path(neg.get("selfLink"), project, "networkEndpointGroups")
        cloud_run = neg.get("cloudRun")
        if cloud_run is None:
            continue
        if not isinstance(cloud_run, dict):
            raise ToolError("Serverless backend metadata has an unsupported shape.")
        if reference and f"/regions/{region}/" in reference:
            if cloud_run.get("urlMask"):
                gaps.append("A regional URL-mask NEG could not be associated with a specific Cloud Run service.")
            elif cloud_run.get("service") == service:
                linked.add(reference)
    indexed = {}
    for policy in policies:
        reference = resource_path(policy.get("selfLink"), project, "securityPolicies")
        if reference:
            if reference in indexed:
                raise ToolError("Duplicate security policy metadata; no passing review produced.")
            indexed[reference] = policy
    for backend in backends:
        groups = backend.get("backends", [])
        if not isinstance(groups, list) or any(not isinstance(group, dict) for group in groups):
            raise ToolError("Backend group metadata has an unsupported shape.")
        if not any(resource_path(group.get("group"), project, "networkEndpointGroups") in linked for group in groups):
            continue
        name = backend.get("name", "")
        if not isinstance(name, str) or not re.fullmatch(NAME, name):
            raise ToolError("Backend name is invalid; raw value withheld.")
        log = backend.get("logConfig", {})
        if not isinstance(log, dict):
            raise ToolError("Backend logging metadata has an unsupported shape.")
        enabled = log.get("enable")
        logging = "enabled" if enabled is True else "disabled" if enabled is False else "unknown"
        sample_rate = log.get("sampleRate")
        if sample_rate is not None and (type(sample_rate) not in (int, float) or not 0 <= sample_rate <= 1):
            raise ToolError("Backend logging sample rate is invalid.")
        attached = bool(backend.get("securityPolicy"))
        policy = indexed.get(resource_path(backend.get("securityPolicy"), project, "securityPolicies"))
        row = {"backend": name, "policy_state": "not_attached", "logging": logging,
               "logging_sample_rate": sample_rate,
               "xss_enforced_references": 0, "xss_preview_references": 0,
               "sqli_enforced_references": 0, "sqli_preview_references": 0,
               "rate_limit_rules": 0, "unparsed_expressions": 0, "shadowed_waf_rules": 0}
        if backend.get("edgeSecurityPolicy"):
            gaps.append(f"Backend {name}: an edge policy is attached but not assessed.")
        if not attached:
            gaps.append(f"Backend {name}: no backend security policy is attached; Cloud Armor protection is not established.")
        if attached and (policy is None or policy.get("type") != "CLOUD_ARMOR"):
            row["policy_state"] = "unresolved"
            gaps.append(f"Backend {name}: attached backend policy could not be resolved as CLOUD_ARMOR.")
        elif policy is not None:
            row["policy_state"] = "observed"
            rules = policy.get("rules")
            if not isinstance(rules, list) or len(rules) > 1000:
                raise ToolError("Security policy rules are missing or exceed the review limit.")
            if any(not isinstance(rule, dict) or type(rule.get("priority")) is not int
                   or not 0 <= rule["priority"] <= 2147483647 for rule in rules):
                raise ToolError("Security policy rule priorities are invalid.")
            if len({rule["priority"] for rule in rules}) != len(rules):
                raise ToolError("Duplicate policy priorities; no passing review produced.")
            allow_all = False
            for rule in sorted(rules, key=lambda item: item["priority"]):
                match = rule.get("match", {})
                if not isinstance(match, dict) or type(rule.get("preview", False)) is not bool:
                    raise ToolError("Security policy match or preview metadata is invalid.")
                expr = match.get("expr", {})
                ip_config = match.get("config", {})
                if not isinstance(expr, dict) or not isinstance(ip_config, dict):
                    raise ToolError("Security policy match metadata is invalid.")
                expression = expr.get("expression", "")
                action = rule.get("action", "")
                if not isinstance(expression, str) or not isinstance(action, str):
                    raise ToolError("Security policy expression or action metadata is invalid.")
                preview = rule.get("preview", False)
                family = waf_family(expression)
                # References are counted, not evaluated as CEL or claimed as effective protection.
                if expression and expression.strip() != "true" and family is None:
                    row["unparsed_expressions"] += 1
                if family:
                    suffix = "preview" if preview else "enforced"
                    row[f"{family}_{suffix}_references"] += 1
                if family and not preview and allow_all:
                    row["shadowed_waf_rules"] += 1
                if action in ("throttle", "rate_based_ban") and not preview:
                    row["rate_limit_rules"] += 1
                unconditional = (expression.strip() == "true" and not match.get("versionedExpr")) or (
                    not expression and match.get("versionedExpr") == "SRC_IPS_V1"
                    and ip_config.get("srcIpRanges") == ["*"]
                )
                if action == "allow" and not preview and unconditional:
                    allow_all = True
            if row["shadowed_waf_rules"]:
                findings.append(finding(
                    "Unconditional allow precedes WAF-referencing rules",
                    f"Backend {name}: {row['shadowed_waf_rules']} lower-priority enforced WAF references.",
                    "These later rules in this backend policy are unreachable after its unconditional allow. "
                    "Other security layers were not evaluated; no application exploit was tested.",
                    "Review policy ordering and intended exceptions before changing enforcement.",
                ))
            if row["xss_preview_references"] and not row["xss_enforced_references"]:
                findings.append(finding(
                    "XSS WAF references appear only in preview",
                    f"Backend {name}: XSS-referencing rules are preview-only in this backend policy.",
                    "Preview rules do not enforce their configured actions. This is not proof that the "
                    "application is vulnerable or that other controls are absent.",
                    "Review WAF tuning, false positives and intended enforcement with the policy owner.",
                ))
        if logging == "disabled" or (logging == "enabled" and sample_rate == 0):
            findings.append(finding(
                "Backend request logging is disabled or samples no requests",
                f"Backend {name}: logging is disabled or its enabled sample rate is zero.",
                "Request evidence from this backend may be unavailable for investigation. "
                "This does not mean all cloud audit or application logging is disabled.",
                "Review the required request logging and sampling policy with the service owner.",
            ))
        rows.append(row)
    ingress = annotations.get("run.googleapis.com/ingress", "unknown")
    if ingress not in ("all", "internal", "internal-and-cloud-load-balancing"):
        ingress = "unknown"
    direct = annotations.get("run.googleapis.com/default-url-disabled")
    default_url = "disabled" if direct == "true" else "enabled" if direct == "false" else "unknown"
    if rows and ingress == "unknown":
        gaps.append("Ingress metadata is unavailable; non-load-balancer access could not be assessed.")
    if rows and ingress == "all":
        gaps.append("Ingress permits non-load-balancer paths; Cloud Armor coverage of direct service access is unverified. IAP may still enforce authentication.")
    if not rows:
        gaps.append("No backend explicitly linked to this service was observed; Cloud Armor coverage is not established.")
    result = {
        "schema_version": 1, "kind": "cloud-armor-review",
        "project": config["project"], "target": config["target"]["url"],
        "cloud_project": project, "service": service, "region": region,
        "started_at": started, "finished_at": datetime.now(timezone.utc).isoformat(),
        "status": "incomplete" if gaps else "completed",
        "ingress": ingress, "default_url": default_url,
        "backends": rows, "findings": findings, "gaps": list(dict.fromkeys(gaps)), "note": NOTE,
    }
    validate_review(result)
    return result


def validate_review(result: dict) -> None:
    schema = json.loads(files("vaptkit").joinpath("schemas/armor-review.json").read_text())
    if next(Draft202012Validator(schema).iter_errors(result), None) is not None:
        raise ToolError("Cloud Armor review does not match the sanitized evidence schema; contents withheld.")
    if result["status"] == "completed" and (
        result["gaps"] or not result["backends"]
        or any(item["policy_state"] != "observed" for item in result["backends"])
    ):
        raise ToolError("A completed Cloud Armor inventory needs linked backends and no collection gaps.")
