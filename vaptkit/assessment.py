import hashlib
import http.client
import ipaddress
import json
import socket
import ssl
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from .process import ToolError


def digest(config: dict) -> str:
    return hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()


def approval_template(config: dict) -> dict:
    return {
        "project": config["project"],
        "config_sha256": digest(config),
        "approved_by": "REPLACE_WITH_AUTHORIZED_OWNER",
        "starts_at": "REPLACE_WITH_UTC_START",
        "expires_at": "REPLACE_WITH_UTC_END",
        "method": "HEAD",
        "paths": ["/"],
        "interval_seconds": 2,
    }


def utc(value: str) -> datetime:
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if result.tzinfo is None:
            raise ValueError
        return result.astimezone(timezone.utc)
    except (ValueError, AttributeError):
        raise ToolError("Approval timestamps must be ISO 8601 with a timezone.") from None


def validate_approval(config: dict, approval: dict, now=None) -> None:
    expected = set(approval_template(config))
    if not isinstance(approval, dict) or set(approval) != expected:
        raise ToolError("Approval fields do not match the scope template.")
    if approval["project"] != config["project"] or approval["config_sha256"] != digest(config):
        raise ToolError("Approval does not match this exact project configuration.")
    owner = approval["approved_by"]
    if not isinstance(owner, str) or not owner.strip() or owner.startswith("REPLACE_"):
        raise ToolError("An authorized owner must approve the scope.")
    if approval["method"] != "HEAD":
        raise ToolError("This runner supports HEAD observations only.")
    start, end = utc(approval["starts_at"]), utc(approval["expires_at"])
    now = now or datetime.now(timezone.utc)
    if not start <= now < end or (end - start).total_seconds() > 14400:
        raise ToolError("Scope must be active and expire within four hours of its start.")
    interval = approval["interval_seconds"]
    if type(interval) not in (int, float) or not 1 <= interval <= 30:
        raise ToolError("Request interval must be between 1 and 30 seconds.")
    paths = approval["paths"]
    if not isinstance(paths, list) or not 1 <= len(paths) <= 10:
        raise ToolError("Approve between 1 and 10 exact paths.")
    if any(not isinstance(path, str) for path in paths) or len(set(paths)) != len(paths):
        raise ToolError("Approval paths must be unique strings.")
    for path in paths:
        if (
            not path.startswith("/") or path.startswith("//") or len(path) > 256
            or any(char.isspace() or ord(char) < 32 for char in path)
            or any(char in path for char in ("?", "#", "%", "\\"))
            or any(part in (".", "..") for part in path.split("/"))
            or any(path.startswith(prefix) for prefix in config["scope"]["excluded_prefixes"])
        ):
            raise ToolError("An approved path is invalid or excluded by project scope.")


def load_json(path: Path, limit=1_000_000):
    try:
        with path.open("rb") as stream:
            raw = stream.read(limit + 1)
        if len(raw) > limit:
            raise ToolError("Input exceeds the size limit.")
        return json.loads(raw)
    except (OSError, ValueError):
        raise ToolError("Cannot read valid JSON input; contents withheld.") from None


def create_output(path: Path) -> None:
    try:
        path.mkdir(mode=0o700, parents=False, exist_ok=False)
    except OSError:
        raise ToolError("Output must be a new directory inside an existing private parent.") from None


def write_private(path: Path, content: str | bytes) -> None:
    import os
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(content.encode() if isinstance(content, str) else content)


def observe(host: str, path: str) -> dict:
    addresses = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    ips = list(dict.fromkeys(address[4][0] for address in addresses))
    if not ips or any(not ipaddress.ip_address(ip).is_global for ip in ips):
        raise ToolError("Target DNS must resolve exclusively to public addresses.")
    context = ssl.create_default_context()
    connection = http.client.HTTPSConnection(host, 443, timeout=10, context=context)
    try:
        # Pin the validated IP while verifying TLS against the configured hostname.
        raw = socket.create_connection((ips[0], 443), timeout=10)
        try:
            connection.sock = context.wrap_socket(raw, server_hostname=host)
        except (OSError, ssl.SSLError):
            raw.close()
            raise
        connection.request("HEAD", path, headers={"User-Agent": "Matt-VAPT-Kit/0.2 (approved-header-check)"})
        response = connection.getresponse()
        csp = response.getheader("Content-Security-Policy", "")
        checks = {
            "html_response": "text/html" in response.getheader("Content-Type", "").lower(),
            "hsts_present": bool(response.getheader("Strict-Transport-Security")),
            "csp_present": bool(csp),
            "nosniff": response.getheader("X-Content-Type-Options", "").lower() == "nosniff",
            "frame_policy_present": bool(response.getheader("X-Frame-Options")) or "frame-ancestors" in csp,
        }
        # Do not retain cookies, URLs, arbitrary headers or response bodies.
        return {"path": path, "method": "HEAD", "status": response.status, "checks": checks}
    finally:
        connection.close()


def findings_for(observation: dict) -> list[dict]:
    if not 200 <= observation["status"] < 300:
        return []
    checks = observation["checks"]
    findings = []
    candidates = [
        ("hsts_present", "HSTS header not observed",
         "Browsers may not be instructed to require HTTPS on later visits. This is a configuration observation, not proof of a downgrade attack.",
         "Review HTTPS-only policy and configure an appropriate HSTS header."),
        ("nosniff", "MIME-sniffing protection not observed",
         "The response did not advertise nosniff. Risk depends on the content being served.",
         "Return X-Content-Type-Options: nosniff where appropriate."),
    ]
    if checks["html_response"]:
        candidates += [
            ("csp_present", "Content Security Policy not observed",
             "A browser defense against script injection is absent on this response. No script injection was tested.",
             "Design and test a Content Security Policy for the application."),
            ("frame_policy_present", "Framing policy not observed",
             "The page may lack browser framing restrictions. Clickjacking was not tested.",
             "Review framing requirements and set frame-ancestors or X-Frame-Options."),
        ]
    for key, title, impact, fix in candidates:
        if not checks[key]:
            findings.append({
                "title": title, "severity": "low", "verification": "observation",
                "category": "configuration", "path": observation["path"],
                "impact": impact, "remediation": fix,
            })
    return findings


def assess(config: dict, approval: dict, output: Path) -> tuple[Path, int]:
    validate_approval(config, approval)
    create_output(output)
    observations, findings, errors = [], [], []
    start = datetime.now(timezone.utc).isoformat()
    host = urlsplit(config["target"]["url"]).hostname
    for index, path in enumerate(approval["paths"]):
        try:
            if index:
                time.sleep(approval["interval_seconds"])
            validate_approval(config, approval)
            observation = observe(host, path)
        except (ToolError, OSError, http.client.HTTPException) as error:
            kind = "scope" if isinstance(error, ToolError) else "transport"
            errors.append({"path": path, "kind": kind, "message": "Check failed; remaining requests stopped. No security conclusion."})
            break
        observations.append(observation)
        findings.extend(findings_for(observation))
        status = observation["status"]
        if not 200 <= status < 300:
            errors.append({"path": path, "kind": "http", "message": f"HTTP {status}; header policy not assessed for this response."})
        if status in (401, 403, 429) or status >= 500:
            errors[-1]["message"] = f"HTTP {status}; stopped to avoid further traffic."
            break
    result = {
        "schema_version": 1, "project": config["project"], "target": config["target"]["url"],
        "started_at": start, "finished_at": datetime.now(timezone.utc).isoformat(),
        "status": "incomplete" if errors else "completed",
        "profile": "unauthenticated-head-only",
        "scope_sha256": hashlib.sha256(json.dumps(approval, sort_keys=True).encode()).hexdigest(),
        "approved_paths": approval["paths"],
        "observations": observations, "findings": findings, "errors": errors,
        "coverage": {
            "data_exposure": "not_tested", "unauthorized_access": "not_tested",
            "note": "Only HEAD response metadata was observed. No bodies, login, role/ownership, workflow, infrastructure or historical breach testing.",
        },
    }
    destination = output / "assessment.json"
    write_private(destination, json.dumps(result, indent=2))
    return destination, 1 if errors else 0
