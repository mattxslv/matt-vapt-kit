import hashlib
import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import time
from datetime import datetime, timezone
from importlib.metadata import version
from pathlib import Path
from urllib.parse import urlsplit

from .headers import grade
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
        "request_timeout_seconds": 30,
        "exposure_checks": False,
    }


def utc(value: str) -> datetime:
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if result.tzinfo is None:
            raise ValueError
        return result.astimezone(timezone.utc)
    except (ValueError, AttributeError, OverflowError):
        raise ToolError("Approval timestamps must be ISO 8601 with a timezone.") from None


def validate_approval(config: dict, approval: dict, now=None) -> None:
    expected = set(approval_template(config))
    required = expected - {"request_timeout_seconds", "exposure_checks"}
    if not isinstance(approval, dict) or not required <= set(approval) <= expected:
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
    timeout = approval.get("request_timeout_seconds", 10)
    if type(timeout) not in (int, float) or not 1 <= timeout <= 60:
        raise ToolError("Request timeout must be between 1 and 60 seconds.")
    if type(approval.get("exposure_checks", False)) is not bool:
        raise ToolError("exposure_checks must be true or false.")
    if approval.get("exposure_checks") and config.get("access"):
        raise ToolError("Public exposure checks require an unauthenticated project configuration.")
    paths = approval["paths"]
    if not isinstance(paths, list) or not 1 <= len(paths) <= 10:
        raise ToolError("Approve between 1 and 10 exact paths.")
    if any(not isinstance(path, str) for path in paths) or len(set(paths)) != len(paths):
        raise ToolError("Approval paths must be unique strings.")
    for path in paths:
        if (
            not path.startswith("/") or path.startswith("//") or len(path) > 256
            or any(char.isspace() or not 33 <= ord(char) <= 126 for char in path)
            or any(char in path for char in ("?", "#", "%", "\\"))
            or any(part in (".", "..") for part in path.split("/"))
            or any(path.startswith(prefix) for prefix in config["scope"]["excluded_prefixes"])
        ):
            raise ToolError("An approved path is invalid or excluded by project scope.")


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON keys are not allowed.")
        result[key] = value
    return result


def reject_constant(value):
    raise ValueError("Non-finite JSON numbers are not allowed.")


def load_json(path: Path, limit=1_000_000):
    try:
        with path.open("rb") as stream:
            raw = stream.read(limit + 1)
        if len(raw) > limit:
            raise ToolError("Input exceeds the size limit.")
        return json.loads(raw, object_pairs_hook=unique_object, parse_constant=reject_constant)
    except (OSError, ValueError, RecursionError):
        raise ToolError("Cannot read valid JSON input; contents withheld.") from None


def create_output(path: Path) -> None:
    try:
        path.mkdir(mode=0o700, parents=False, exist_ok=False)
    except OSError:
        raise ToolError("Output must be a new directory inside an existing private parent.") from None


def write_private(path: Path, content: str | bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(content.encode() if isinstance(content, str) else content)


def access_headers(config: dict) -> dict[str, str]:
    access = config.get("access")
    if access is None:
        return {}
    token = os.environ.get(access["token_env"], "")
    if not token or len(token) > 16384 or not re.fullmatch(r"[A-Za-z0-9._~+/-]+=*", token):
        raise ToolError("Access token is missing or invalid in the configured environment variable; value withheld.")
    return {access["header"]: "Bearer " + token}


def remaining_timeout(expires_at: datetime | None, timeout_seconds: float = 10) -> float:
    if expires_at is None:
        return timeout_seconds
    seconds = (expires_at - datetime.now(timezone.utc)).total_seconds()
    if seconds <= 0:
        raise ToolError("Approval expired; request stopped.")
    return min(timeout_seconds, seconds)


def public_addresses(host: str) -> list[str]:
    addresses = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    ips = list(dict.fromkeys(address[4][0] for address in addresses))
    if not ips or any(not ipaddress.ip_address(ip).is_global for ip in ips):
        raise ToolError("Target DNS must resolve exclusively to public addresses.")
    return ips


def request(host: str, method: str, path: str, *, headers=None, expires_at=None,
            timeout_seconds=10, body=None, body_limit=0) -> tuple[int, dict[str, list[str]], bytes]:
    """One pinned, verified HTTPS request. Redirects are never followed."""
    ips = public_addresses(host)
    context = ssl.create_default_context()
    connection = http.client.HTTPSConnection(
        host, 443, timeout=remaining_timeout(expires_at, timeout_seconds), context=context
    )
    try:
        # Pin the validated IP while verifying TLS against the configured hostname.
        raw = socket.create_connection((ips[0], 443), timeout=remaining_timeout(expires_at, timeout_seconds))
        try:
            connection.sock = context.wrap_socket(raw, server_hostname=host)
        except (OSError, ssl.SSLError):
            raw.close()
            raise
        connection.sock.settimeout(remaining_timeout(expires_at, timeout_seconds))
        connection.request(method, path, body=body, headers={
            "User-Agent": f"Matt-VAPT-Kit/{version('matt-vapt-kit')} (approved-check)", **(headers or {}),
        })
        response = connection.getresponse()
        remaining_timeout(expires_at)
        collected: dict[str, list[str]] = {}
        for name, value in response.getheaders():
            collected.setdefault(name.lower(), []).append(value)
        data = bytearray()
        if method != "HEAD":
            while len(data) < body_limit:
                connection.sock.settimeout(remaining_timeout(expires_at, timeout_seconds))
                chunk = response.read1(min(16384, body_limit - len(data)))
                remaining_timeout(expires_at)
                if not chunk:
                    break
                data.extend(chunk)
        return response.status, collected, bytes(data)
    finally:
        connection.close()


def observe(host: str, path: str, *, headers=None, expires_at=None, timeout_seconds=10) -> dict:
    status, received, _ = request(
        host, "HEAD", path, headers=headers, expires_at=expires_at, timeout_seconds=timeout_seconds,
    )
    # Only derived booleans are kept: no cookies, URLs, raw headers or bodies.
    return {"path": path, "method": "HEAD", "status": status, "checks": grade(received)}


def failure_detail(error: Exception) -> tuple[str, str]:
    if isinstance(error, HTTPStop):
        return "http", http_gap(error.status, False)
    if isinstance(error, ToolError):
        return "scope", "Scope or public-address validation failed; remaining requests stopped."
    if isinstance(error, ssl.SSLCertVerificationError):
        return "transport", "TLS certificate verification failed; remaining requests stopped."
    if isinstance(error, ssl.SSLError):
        return "transport", "TLS negotiation failed; remaining requests stopped."
    if isinstance(error, socket.gaierror):
        return "transport", "DNS resolution failed; remaining requests stopped."
    if isinstance(error, TimeoutError):
        return "transport", "Network timeout; remaining requests stopped."
    return "transport", "Connection or HTTP protocol failed; remaining requests stopped."


class HTTPStop(ToolError):
    def __init__(self, path: str, status: int):
        self.path = path
        self.status = status
        super().__init__(f"HTTP {status}: remaining requests stopped.")


def stop_on_http(path: str, status: int) -> None:
    if 300 <= status < 400 or status in (401, 403, 429) or status >= 500:
        raise HTTPStop(path, status)


def http_gap(status: int, authenticated: bool) -> str:
    if 300 <= status < 400:
        return f"HTTP {status}: redirect not followed. Application coverage is blocked; verify the approved login and path."
    if status in (401, 403):
        reason = "configured credential was not accepted or lacks access" if authenticated else "authentication or access is required"
        return f"HTTP {status}: {reason}. Stopped; do not disable access controls."
    if status == 429:
        return "HTTP 429: server rate limit reached. Stopped; retry only in a new approved window."
    if status >= 500:
        return f"HTTP {status}: server error. Stopped to avoid further traffic."
    return f"HTTP {status}: header policy not assessed for this response."


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
    graded = [
        ("hsts_strong", "hsts_present", "HSTS max-age is shorter than 180 days",
         "Browsers forget the HTTPS-only rule quickly, leaving a window for downgrade on later visits.",
         "Set Strict-Transport-Security max-age to at least 15552000 (31536000 recommended)."),
        ("referrer_policy_safe", None, "Referrer policy can leak full URLs",
         "Full page URLs, including any tokens in query strings, may be sent to other sites.",
         "Use Referrer-Policy: strict-origin-when-cross-origin or stricter."),
        ("cookies_secure", None, "Cookie set without the Secure flag",
         "The cookie may be sent over plain HTTP if a user is ever downgraded.",
         "Add the Secure attribute to every cookie set by the application."),
        ("session_cookies_httponly", None, "Session-like cookie readable by scripts",
         "A script injection flaw could steal the session cookie. Cookie names suggest session use; confirm.",
         "Add HttpOnly to session and authentication cookies."),
        ("no_version_disclosure", None, "Server technology or version disclosed in headers",
         "X-Powered-By or a versioned Server header helps attackers pick known exploits.",
         "Remove X-Powered-By (Next.js: poweredByHeader: false) and strip versions from Server."),
    ]
    if checks["html_response"]:
        graded += [
            ("csp_script_strong", "csp_present", "Content Security Policy allows unsafe scripts",
             "The policy permits inline, eval or wildcard scripts, so it gives little protection against script injection.",
             "Remove 'unsafe-inline', 'unsafe-eval' and wildcard script sources; use nonces or hashes."),
            ("frame_policy_strong", "frame_policy_present", "Framing policy allows any origin",
             "The page can be embedded by other sites, so clickjacking defenses are ineffective.",
             "Use frame-ancestors 'none' or 'self' (or X-Frame-Options DENY/SAMEORIGIN)."),
        ]
    for key, requires, title, impact, fix in graded:
        # Older records lack graded keys; only grade a header that is actually present.
        if key in checks and not checks[key] and (requires is None or checks[requires]):
            candidates.append((key, title, impact, fix))
    for key, title, impact, fix in candidates:
        if not checks[key]:
            findings.append({
                "title": title, "severity": "low", "verification": "observation",
                "category": "configuration", "path": observation["path"],
                "impact": impact, "remediation": fix, "check_id": key,
            })
    return findings


def verify(findings: list[dict], observations: list[dict], reobserve, retest_paths=()) -> list[dict]:
    """Re-request each path with findings once; keep only reproducible results as confirmed."""
    verified = []
    paths = list(dict.fromkeys([item["path"] for item in findings] + list(retest_paths)))
    for path in paths:
        observation = reobserve(path)
        observations.append(observation)
        if not 200 <= observation["status"] < 300:
            raise HTTPStop(path, observation["status"])
        again = {item["title"] for item in findings_for(observation)}
        for finding in (item for item in findings if item["path"] == path):
            reproduced = finding["title"] in again
            verified.append({
                **finding, "verification": "confirmed" if reproduced else "suspected",
                "evidence": "Reproduced on a second request." if reproduced else
                "Not reproduced on a second request; may differ by edge server or cache.",
            })
    return verified


def compare(baseline: dict, result: dict) -> list[dict]:
    current = {(item["title"], item["path"]): item for item in result["findings"]}
    old_headers = {
        (item["title"], item["path"]): item["check_id"]
        for observation in baseline["observations"] for item in findings_for(observation)
    }
    first = {item["path"]: item for item in result["observations"]}
    second = {item["path"]: item for item in result.get("verification_observations", [])}
    old_exposure = {item["path"] for item in baseline.get("exposure", []) if item["exposed"]}
    exposure = {item["path"]: item for item in result.get("exposure", [])}
    rows = []
    for item in baseline.get("findings", []):
        key = (item["title"], item["path"])
        status = "not_rechecked"
        if key in current:
            if current[key]["verification"] == "confirmed":
                status = "still_present"
        elif key in old_headers:
            check_id = old_headers[key]
            attempts = [first.get(item["path"]), second.get(item["path"])]
            if all(attempt and 200 <= attempt["status"] < 300
                   and attempt["checks"].get(check_id) is True for attempt in attempts):
                status = "resolved"
        elif item["path"] in old_exposure:
            checked = exposure.get(item["path"])
            if checked and checked["status"] in (404, 410):
                status = "resolved"
        rows.append({"title": item["title"][:200], "path": item["path"][:256], "status": status})
    return rows


def assess(config: dict, approval: dict, output: Path, baseline: dict | None = None) -> tuple[Path, int]:
    validate_approval(config, approval)
    if baseline is not None:
        from .report import validate_result
        validate_result(baseline)
        if baseline["project"] != config["project"] or baseline["target"] != config["target"]["url"]:
            raise ToolError("Baseline assessment belongs to another project or target.")
    if output.exists():
        raise ToolError("Output must be a new directory; existing assessment retained.")
    access = config.get("access", {}).get("type")
    profile = ("unauthenticated-exposure" if approval.get("exposure_checks") else
               "iap-browser-head-only" if access == "iap-browser" else
               "bearer-head-only" if access else "unauthenticated-head-only")
    if baseline is not None and baseline["profile"] != profile:
        raise ToolError("Retest requires the same access and assessment profile as the baseline.")
    if config.get("access", {}).get("type") == "iap-browser":
        from .browser_login import login
        headers = login(config, approval)
    else:
        headers = access_headers(config)
    validate_approval(config, approval)
    create_output(output)
    observations, findings, errors, exposure, verification_observations, requests = [], [], [], [], [], []
    start = datetime.now(timezone.utc).isoformat()
    host = urlsplit(config["target"]["url"]).hostname
    expires_at = utc(approval["expires_at"])
    timeout = approval.get("request_timeout_seconds", 10)

    def recorded_request(host, method, path, **kwargs):
        status, received, body = request(host, method, path, **kwargs)
        requests.append({"method": method, "path": path, "status": status})
        stop_on_http(path, status)
        return status, received, body

    def reobserve(path):
        time.sleep(approval["interval_seconds"])
        validate_approval(config, approval)
        item = observe(host, path, headers=headers, expires_at=expires_at, timeout_seconds=timeout)
        requests.append({"method": "HEAD", "path": path, "status": item["status"]})
        return item

    for index, path in enumerate(approval["paths"]):
        try:
            if index:
                time.sleep(approval["interval_seconds"])
            validate_approval(config, approval)
            observation = observe(host, path, headers=headers, expires_at=expires_at, timeout_seconds=timeout)
        except (ToolError, OSError, http.client.HTTPException) as error:
            kind, message = failure_detail(error)
            errors.append({"path": path, "kind": kind, "message": message})
            break
        observations.append(observation)
        requests.append({"method": "HEAD", "path": path, "status": observation["status"]})
        findings.extend(findings_for(observation))
        status = observation["status"]
        if not 200 <= status < 300:
            errors.append({"path": path, "kind": "http", "message": http_gap(status, bool(headers))})
        if 300 <= status < 400 or status in (401, 403, 429) or status >= 500:
            break
    if not errors:
        try:
            retest_paths = [
                item["path"] for item in (baseline or {}).get("observations", [])
                if item["path"] in approval["paths"] and findings_for(item)
            ]
            findings = verify(findings, verification_observations, reobserve, retest_paths)
            if approval.get("exposure_checks"):
                from . import exposure as exposure_checks

                def pause():
                    time.sleep(approval["interval_seconds"])
                    validate_approval(config, approval)
                exposure_checks.run(config, approval, host, {}, recorded_request, expires_at, pause,
                                    records=exposure, findings=findings)
        except (ToolError, OSError, http.client.HTTPException) as error:
            kind, message = failure_detail(error)
            errors.append({"path": error.path if isinstance(error, HTTPStop) else "/",
                           "kind": kind, "message": "Verification or exposure stage: " + message})
    result = {
        "schema_version": 1, "project": config["project"], "target": config["target"]["url"],
        "started_at": start, "finished_at": datetime.now(timezone.utc).isoformat(),
        "status": "incomplete" if errors else "completed",
        "profile": profile,
        "scope_sha256": hashlib.sha256(json.dumps(approval, sort_keys=True).encode()).hexdigest(),
        "approved_paths": approval["paths"],
        "observations": observations, "findings": findings, "errors": errors,
        "verification_observations": verification_observations, "requests": requests,
        "coverage": {
            "data_exposure": "tested" if exposure and not errors else "not_tested",
            "unauthorized_access": "not_tested",
            "note": (
                "Google IAP access used a dedicated browser session before the assessment; normal login page requests are outside HEAD check counts. "
                if profile == "iap-browser-head-only" else ""
            ) + "Header values were graded. Confirmation requires a repeated observation; errors may prevent verification. "
            + ("Public exposure checks were enabled for a fixed list, a random-path baseline and up to three discovered source maps. Signatures use at most 2 KB; bodies are not stored. This is not comprehensive data-exposure coverage. "
               if approval.get("exposure_checks") else "")
            + "No application-login, role/ownership, workflow, infrastructure or historical breach testing.",
        },
    }
    if exposure:
        result["exposure"] = exposure
    if baseline is not None:
        result["retest"] = compare(baseline, result)
    destination = output / "assessment.json"
    write_private(destination, json.dumps(result, indent=2))
    return destination, 1 if errors else 0
