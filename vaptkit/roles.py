"""Bounded DTAP cookie-session role checks using explicitly approved staging accounts."""
import http.client
import getpass
import json
import os
import re
import time
import sys
import warnings
from datetime import datetime, timezone
from http.cookies import CookieError, SimpleCookie
from pathlib import Path
from urllib.parse import urlsplit

from .assessment import (
    HTTPStop, approval_template, create_output, digest, failure_detail, reject_constant,
    request, unique_object, utc, validate_approval, write_private,
)
from .browser_login import login as browser_login
from .exposure import content_class
from .process import ToolError
from .service_login import ServiceAccountAccess

LOGIN = "/api/auth/signin"
LOGOUT = "/api/auth/signout"
BODY_LIMIT = 65536
COOKIE_NAMES = ("auth-token", "session-bind")


def template(config: dict) -> dict:
    result = approval_template(config)
    result.update(method="GET", role_login=False,
                  role_accounts=[item["id"] for item in config.get("role_testing", {}).get("accounts", [])],
                  paths=[item["path"] for item in config.get("role_testing", {}).get("routes", [])])
    return result


def validate(config: dict, approval: dict) -> None:
    settings = config.get("role_testing")
    if not settings or settings["adapter"] != "dtap-cookie-v1":
        raise ToolError("Role checks require the DTAP cookie adapter.")
    if config.get("access") and config["access"]["type"] not in ("iap-browser", "iap-service-account"):
        raise ToolError("Role checks support browser or keyless IAP gateway access, not bearer access.")
    if not isinstance(approval, dict) or approval.get("role_login") is not True or approval.get("method") != "GET":
        raise ToolError("Role checks require explicit role_login approval and GET paths.")
    head_scope = {key: value for key, value in approval.items() if key not in ("role_login", "role_accounts")}
    head_scope["method"] = "HEAD"
    if head_scope.get("exposure_checks"):
        raise ToolError("Role and public exposure checks need separate approvals.")
    validate_approval(config, head_scope)
    accounts = approval.get("role_accounts")
    known = {item["id"]: item for item in settings["accounts"]}
    if (not isinstance(accounts, list) or not 1 <= len(accounts) <= 8
            or any(not isinstance(item, str) or item not in known for item in accounts)
            or len(set(accounts)) != len(accounts)):
        raise ToolError("Approve between one and eight distinct configured account IDs.")
    routes = {item["path"]: item for item in settings["routes"]}
    selected_roles = {known[item]["role"] for item in accounts}
    for path in approval["paths"]:
        if path not in routes or not selected_roles.intersection(routes[path]["allowed_roles"]):
            raise ToolError("Every approved route needs a configured allowed-role positive control.")
    for path in (LOGIN, LOGOUT):
        if any(path.startswith(prefix) for prefix in config["scope"]["excluded_prefixes"]):
            raise ToolError("Role sign-in or sign-out is excluded by project scope.")


def credentials(config: dict, approval: dict, *, prompt_passwords=False) -> dict:
    selected = set(approval["role_accounts"])
    result, emails, passwords = {}, set(), {}
    accounts = [account for account in config["role_testing"]["accounts"] if account["id"] in selected]
    try:
        for account in accounts:
            email = os.environ.get(account["email_env"], "")
            if (not email or len(email) > 254 or email.strip() != email or "@" not in email
                    or any(ord(char) < 33 for char in email)):
                raise ToolError("A role email environment variable is missing or invalid; values withheld.")
            if email.lower() in emails:
                raise ToolError("Each configured account must use a distinct email address; values withheld.")
            emails.add(email.lower())
            result[account["id"]] = {"email": email}
        for account in accounts:
            name = account["password_env"]
            if name not in passwords:
                password = os.environ.get(name, "")
                if not password and prompt_passwords:
                    validate(config, approval)
                    if not sys.stdin.isatty():
                        raise ToolError("Hidden password entry requires an interactive terminal; use the configured environment variables for automation.")
                    try:
                        with warnings.catch_warnings():
                            warnings.simplefilter("error", getpass.GetPassWarning)
                            password = getpass.getpass(f"DTAP QA password ({name}, input hidden): ")
                    except (getpass.GetPassWarning, EOFError, KeyboardInterrupt):
                        raise ToolError("Hidden password entry unavailable or cancelled; no assessment started.") from None
                    validate(config, approval)
                if not password or len(password) > 1024 or password.strip() != password:
                    raise ToolError("A role password is missing or invalid; values withheld.")
                passwords[name] = password
            result[account["id"]]["password"] = passwords[name]
        return result
    finally:
        passwords.clear()


def json_object(body: bytes) -> dict | None:
    if len(body) > BODY_LIMIT:
        return None
    try:
        value = json.loads(body, object_pairs_hook=unique_object, parse_constant=reject_constant)
    except (ValueError, RecursionError):
        return None
    return value if isinstance(value, dict) else None


def matches_shape(headers: dict, body: bytes, shape: dict) -> bool:
    value = json_object(body) if content_class(headers) == "json" else None
    if value is None or value.get("error") or value.get("success") is False:
        return False
    types = {"array": list, "object": dict, "string": str, "boolean": bool, "number": (int, float)}
    return all(key in value and isinstance(value[key], types[kind])
               and not (kind == "number" and isinstance(value[key], bool)) for key, kind in shape.items())


def response_quality(status: int, headers: dict, body: bytes, shape: dict, account: str) -> str:
    value = json_object(body) if content_class(headers) == "json" else None
    if status in (401, 403) and (value is None or (status == 401 and account != "anonymous")):
        return "blocked"
    age = headers.get("age", [])
    cache_status = " ".join(headers.get("x-cache", []) + headers.get("cf-cache-status", []))
    if (age and (len(age) != 1 or not re.fullmatch(r"0+", age[0].strip()))
            or re.search(r"\b(hit|stale|updating|revalidated)\b", cache_status, re.I)):
        return "cached"
    if status in (401, 403):
        if not any(key in value for key in shape) and (value.get("error") or value.get("success") is False):
            return "denied"
        return "unmatched"
    if value is None or not matches_shape(headers, body, shape):
        return "unmatched"
    if any(not value[key] for key, kind in shape.items() if kind == "array"):
        return "empty"
    return "matched"


def role_outcome(record: dict, controls: set[str]) -> str:
    """Classify derived evidence, retaining the original criteria for legacy records."""
    attempts = record["attempts"]
    if not attempts or any(item.get("evidence_quality") == "blocked" for item in attempts):
        return "blocked"
    success = all(200 <= item["status"] < 300 and item["shape_matched"]
                  and item.get("evidence_quality", "matched") == "matched" for item in attempts)
    if record["expected_allowed"]:
        return "allowed" if success else "inconclusive"
    if len(attempts) == 2 and success and record["path"] in controls:
        return "confirmed"
    if all(item["status"] in (401, 403) and item.get("evidence_quality", "denied") == "denied"
           for item in attempts):
        return "denied"
    return "inconclusive"


def collect_cookies(headers: dict, host: str) -> dict[str, str]:
    result = {}
    try:
        for value in headers.get("set-cookie", []):
            parsed = SimpleCookie()
            parsed.load(value)
            for name in COOKIE_NAMES:
                if name not in parsed:
                    continue
                cookie = parsed[name]
                if (name in result or cookie["domain"] not in ("", host) or cookie["path"] != "/"
                        or not cookie["secure"] or not cookie["httponly"]
                        or not re.fullmatch(r"[A-Za-z0-9._~+/-]{1,16384}=*", cookie.value)):
                    raise ToolError("Login returned invalid or unsupported session cookies; values withheld.")
                result[name] = cookie.value
    except CookieError:
        raise ToolError("Login cookie parsing failed; values withheld.") from None
    return result


def run(config: dict, approval: dict, output: Path, *, prompt_passwords=False) -> tuple[Path, int]:
    validate(config, approval)
    if output.exists() or not output.parent.is_dir():
        raise ToolError("Output must be a new directory inside an existing private parent.")
    secrets = credentials(config, approval, prompt_passwords=prompt_passwords)
    validate(config, approval)
    create_output(output)
    started = datetime.now(timezone.utc).isoformat()
    host = urlsplit(config["target"]["url"]).hostname
    expires = utc(approval["expires_at"])
    timeout = approval.get("request_timeout_seconds", 10)
    settings = config["role_testing"]
    accounts = {item["id"]: item for item in settings["accounts"]}
    routes = {item["path"]: item for item in settings["routes"]}
    records, requests, errors, cleanup = [], [], [], []
    active_path = LOGIN
    first = True
    stop_cleanup = False
    gateway_headers = {}
    gateway_session = None

    def call(method, path, cookies=None, body=None):
        nonlocal active_path, first, stop_cleanup
        active_path = path
        if not first:
            time.sleep(approval["interval_seconds"])
        first = False
        try:
            validate(config, approval)
            access = gateway_session.headers() if gateway_session else gateway_headers
            headers = {"Accept": "application/json", "Cache-Control": "no-cache", **access}
            if cookies:
                headers["Cookie"] = "; ".join(
                    ([access["Cookie"]] if access.get("Cookie") else [])
                    + [f"{name}={value}" for name, value in cookies.items()]
                )
            if body is not None:
                headers["Content-Type"] = "application/json"
            status, received, data = request(
                host, method, path, headers=headers, body=body, body_limit=BODY_LIMIT + 1,
                expires_at=expires, timeout_seconds=timeout,
            )
        except (ToolError, OSError, http.client.HTTPException):
            stop_cleanup = True
            raise
        requests.append({"method": method, "path": path, "status": status})
        if 300 <= status < 400 or status == 429 or status >= 500:
            stop_cleanup = True
            raise HTTPStop(path, status)
        return status, received, data

    def inspect(account_id, role, cookies=None):
        nonlocal stop_cleanup
        for path in approval["paths"]:
            route = routes[path]
            expected = role in route["allowed_roles"]
            attempts = []
            record = {"account": account_id, "role": role, "path": path,
                      "expected_allowed": expected, "attempts": attempts}
            records.append(record)
            for attempt in range(2):
                try:
                    status, headers, body = call("GET", path, cookies)
                except HTTPStop as error:
                    attempts.append({"status": error.status, "content_class": "none",
                                     "shape_matched": False, "evidence_quality": "blocked"})
                    raise
                matched = matches_shape(headers, body, route["response_shape"])
                quality = response_quality(status, headers, body, route["response_shape"], account_id)
                attempts.append({"status": status, "content_class": content_class(headers),
                                 "shape_matched": matched, "evidence_quality": quality})
                if quality == "blocked":
                    stop_cleanup = True
                    raise ToolError("Session or gateway denial could not establish application role policy; requests stopped.")
                if not 200 <= status < 300 or expected:
                    break

    def error_record(error):
        kind, message = failure_detail(error)
        if isinstance(error, ToolError) and not isinstance(error, HTTPStop):
            message = str(error)
        errors.append({"path": error.path if isinstance(error, HTTPStop) else active_path,
                       "kind": kind, "message": message[:256]})

    try:
        if config.get("access", {}).get("type") == "iap-service-account":
            gateway_session = ServiceAccountAccess(config, approval, validate_scope=validate)
        elif config.get("access"):
            gateway_headers = browser_login(config, approval, validate_scope=validate)
        inspect("anonymous", "anonymous")
        for account_id in approval["role_accounts"]:
            account = accounts[account_id]
            session = {}
            attempted_login = False
            try:
                attempted_login = True
                status, headers, body = call("POST", LOGIN, body=json.dumps(secrets[account_id]).encode())
                session = collect_cookies(headers, host)
                if not 200 <= status < 300:
                    raise HTTPStop(LOGIN, status)
                identity = json_object(body) if content_class(headers) == "json" else None
                user = identity.get("user") if identity else None
                if (not isinstance(user, dict) or not isinstance(user.get("email"), str)
                        or user["email"].lower() != secrets[account_id]["email"].lower()
                        or user.get("user_type") != account["role"] or (identity and identity.get("error"))
                        or set(session) != set(COOKIE_NAMES)):
                    raise ToolError("Login identity, role or required session cookies did not match; values withheld.")
                inspect(account_id, account["role"], session)
            finally:
                if session and not stop_cleanup:
                    try:
                        status, headers, body = call("POST", LOGOUT, session, body=b"{}")
                        acknowledged = (200 <= status < 300 and content_class(headers) == "json"
                                        and (json_object(body) or {}).get("success") is True)
                        cleanup.append({"account": account_id, "status": "acknowledged" if acknowledged else "unconfirmed"})
                        if not acknowledged:
                            raise ToolError("Sign-out was not acknowledged; manual session cleanup may be required.")
                    except (ToolError, OSError, http.client.HTTPException) as error:
                        error_record(error)
                        if not any(item["account"] == account_id for item in cleanup):
                            cleanup.append({"account": account_id, "status": "unconfirmed"})
                elif attempted_login:
                    cleanup.append({"account": account_id, "status": "unconfirmed"})
                session.clear()
            if errors:
                break
    except (ToolError, OSError, http.client.HTTPException) as error:
        error_record(error)
    finally:
        if gateway_session:
            gateway_session.clear()
        gateway_headers.clear()
        secrets.clear()

    controls = {item["path"] for item in records if role_outcome(item, set()) == "allowed"}
    findings = []
    for item in records:
        outcome = role_outcome(item, controls)
        if outcome in ("inconclusive", "blocked"):
            errors.append({"path": item["path"], "kind": "http",
                           "message": f"Role check for {item['account']} was {outcome}; "
                                      "usable response evidence or an allowed-role control was missing."})
        if item["expected_allowed"] or not any(
            200 <= attempt["status"] < 300 and attempt["shape_matched"]
            and attempt["evidence_quality"] in ("matched", "cached") for attempt in item["attempts"]
        ):
            continue
        confirmed = outcome == "confirmed"
        findings.append({
            "title": f"Unexpected endpoint access for {item['account']}",
            "severity": "high" if confirmed else "medium",
            "verification": "confirmed" if confirmed else "suspected",
            "category": "unauthorized_access", "owasp": "A01", "path": item["path"],
            "impact": "An account outside the configured allowed roles received a successful response. "
                      "This tests endpoint role policy, not record ownership or the sensitivity of returned data.",
            "remediation": "Review the expected role matrix and enforce its policy in middleware and the route.",
            "evidence": ("Two successful responses matched the configured JSON shape with nonempty arrays, "
                         "no observed cache-hit signal and a usable allowed-role control."
                         if confirmed else "A successful response matched the configured shape, but repetition, "
                         "cache evidence or an allowed-role control was inconclusive."),
        })
    expected_count = (len(approval["role_accounts"]) + 1) * len(approval["paths"])
    if len(records) != expected_count and not errors:
        errors.append({"path": "/", "kind": "scope", "message": "The approved role matrix was not fully exercised."})
    if any(item["verification"] == "suspected" for item in findings) and not errors:
        errors.append({"path": "/", "kind": "http", "message": "Unexpected successful responses need manual verification."})
    result = {
        "schema_version": 1, "project": config["project"], "target": config["target"]["url"],
        "started_at": started, "finished_at": datetime.now(timezone.utc).isoformat(),
        "status": "incomplete" if errors else "completed", "profile": "dtap-role-matrix",
        "scope_sha256": digest(approval), "approved_paths": approval["paths"],
        "observations": [], "findings": findings, "errors": errors[:100], "requests": requests,
        "role_accounts": ["anonymous"] + approval["role_accounts"], "role_observations": records,
        "role_cleanup": cleanup,
        "coverage": {"data_exposure": "not_tested", "unauthorized_access": "tested" if not errors else "not_tested",
                     "note": "GET-only endpoint role matrix with anonymous and isolated DTAP cookie sessions. "
                             "POST was limited to approved sign-in and sign-out. Login can create sessions, audit "
                             "records and login counters. No business records were intentionally changed. "
                             "Only status, content class and JSON-shape booleans were retained. "
                             "Derived evidence-quality labels were also retained. Empty arrays, cache-hit signals, "
                             "expired sessions and misleading responses do not establish passing role coverage. "
                             "Only exact approved paths were checked; pagination links were not followed. "
                             "Ownership, workflows and unlisted routes were not tested. "
                             "Sign-out acknowledgement is not proof of server-side session revocation."
                             + (" Google IAP access was configured for every matrix request, including the "
                                "application-anonymous control. Public access outside IAP was not tested. "
                                "DTAP sign-out does not revoke gateway credentials."
                                if config.get("access") else "")
                             + (" Keyless IAP signing was configured through Google IAM Credentials; those requests are outside "
                                "the application matrix request count."
                                if config.get("access", {}).get("type") == "iap-service-account" else "")},
    }
    destination = output / "assessment.json"
    write_private(destination, json.dumps(result, indent=2))
    return destination, 1 if errors else 0
