"""Bounded DTAP cookie-session role checks using explicitly approved staging accounts."""
import http.client
import json
import os
import re
import time
from datetime import datetime, timezone
from http.cookies import CookieError, SimpleCookie
from pathlib import Path
from urllib.parse import urlsplit

from .assessment import (
    HTTPStop, approval_template, create_output, digest, failure_detail, reject_constant,
    request, unique_object, utc, validate_approval, write_private,
)
from .exposure import content_class
from .process import ToolError

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
    if not settings or settings["adapter"] != "dtap-cookie-v1" or config.get("access"):
        raise ToolError("Role checks require the DTAP cookie adapter without gateway access configuration.")
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


def credentials(config: dict, approval: dict) -> dict:
    selected = set(approval["role_accounts"])
    result, emails = {}, set()
    for account in config["role_testing"]["accounts"]:
        if account["id"] not in selected:
            continue
        email = os.environ.get(account["email_env"], "")
        password = os.environ.get(account["password_env"], "")
        if (not email or len(email) > 254 or email.strip() != email or "@" not in email
                or any(ord(char) < 33 for char in email)
                or not password or len(password) > 1024 or password.strip() != password):
            raise ToolError("A role credential environment variable is missing or invalid; values withheld.")
        if email.lower() in emails:
            raise ToolError("Each configured account must use a distinct email address; values withheld.")
        emails.add(email.lower())
        result[account["id"]] = {"email": email, "password": password}
    return result


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


def run(config: dict, approval: dict, output: Path) -> tuple[Path, int]:
    try:
        validate(config, approval)
    except ToolError:
        stop_cleanup = True
        raise
    secrets = credentials(config, approval)
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

    def call(method, path, cookies=None, body=None):
        nonlocal active_path, first, stop_cleanup
        active_path = path
        if not first:
            time.sleep(approval["interval_seconds"])
        first = False
        validate(config, approval)
        headers = {"Accept": "application/json", "Cache-Control": "no-cache"}
        if cookies:
            headers["Cookie"] = "; ".join(f"{name}={value}" for name, value in cookies.items())
        if body is not None:
            headers["Content-Type"] = "application/json"
        try:
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
        for path in approval["paths"]:
            route = routes[path]
            expected = role in route["allowed_roles"]
            attempts = []
            record = {"account": account_id, "role": role, "path": path,
                      "expected_allowed": expected, "attempts": attempts}
            records.append(record)
            for attempt in range(2):
                status, headers, body = call("GET", path, cookies)
                matched = matches_shape(headers, body, route["response_shape"])
                attempts.append({"status": status, "content_class": content_class(headers), "shape_matched": matched})
                if not 200 <= status < 300 or expected:
                    break
            if expected and not (200 <= attempts[0]["status"] < 300 and attempts[0]["shape_matched"]):
                errors.append({"path": path, "kind": "http",
                               "message": "Allowed-role positive control failed or response shape was inconclusive."})
            elif not expected and attempts[0]["status"] not in (401, 403) and not 200 <= attempts[0]["status"] < 300:
                errors.append({"path": path, "kind": "http",
                               "message": "Denied-role check was inconclusive; only 401/403 establishes an explicit denial."})

    def error_record(error):
        kind, message = failure_detail(error)
        if isinstance(error, ToolError) and not isinstance(error, HTTPStop):
            message = str(error)
        errors.append({"path": error.path if isinstance(error, HTTPStop) else active_path,
                       "kind": kind, "message": message[:256]})

    try:
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

    controls = {item["path"] for item in records if item["expected_allowed"] and item["attempts"]
                and 200 <= item["attempts"][0]["status"] < 300 and item["attempts"][0]["shape_matched"]}
    findings = []
    for item in records:
        if item["expected_allowed"] or not any(200 <= attempt["status"] < 300 for attempt in item["attempts"]):
            continue
        confirmed = (len(item["attempts"]) == 2 and item["path"] in controls
                     and all(200 <= attempt["status"] < 300 and attempt["shape_matched"] for attempt in item["attempts"]))
        findings.append({
            "title": f"Unexpected endpoint access for {item['account']}",
            "severity": "high" if confirmed else "medium",
            "verification": "confirmed" if confirmed else "suspected",
            "category": "unauthorized_access", "owasp": "A01", "path": item["path"],
            "impact": "An account outside the configured allowed roles received a successful response. "
                      "This tests endpoint role policy, not record ownership or the sensitivity of returned data.",
            "remediation": "Review the expected role matrix and enforce its policy in middleware and the route.",
            "evidence": ("Two successful responses matched the configured JSON shape and an allowed-role control succeeded."
                         if confirmed else "Successful HTTP response observed, but repeated shape or allowed-role control evidence is missing."),
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
                             "Ownership, workflows and unlisted routes were not tested. "
                             "Sign-out acknowledgement is not proof of server-side session revocation."},
    }
    destination = output / "assessment.json"
    write_private(destination, json.dumps(result, indent=2))
    secrets.clear()
    return destination, 1 if errors else 0
