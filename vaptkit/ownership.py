"""Two-account ownership checks: does one account's write reach another account's own record?

Config-driven and narrow: for each configured check, the target account's current value is read first,
the acting account then attempts to overwrite it by sending the target's own id, the target's value is
re-read to see whether it actually changed, and the original value is restored immediately regardless of
outcome. Runs under its own explicit approval (ownership_login), separate from role_login.
"""
import http.client
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from .assessment import (
    HTTPStop, approval_template, create_output, digest, failure_detail, request, utc, validate_approval,
    write_private,
)
from .exposure import content_class
from .process import ToolError
from .roles import credentials as role_credentials
from .roles import json_object, sign_in, sign_out
from .service_login import ServiceAccountAccess
from .browser_login import login as browser_login

BODY_LIMIT = 65536
PROBE_PREFIX = "MVK-OWNERSHIP-PROBE"


def template(config: dict) -> dict:
    result = approval_template(config)
    checks = config.get("ownership_checks", [])
    paths = sorted({item["write_path"] for item in checks} | {item.get("read_path", item["write_path"]) for item in checks})
    result.update(method="POST", ownership_login=False, paths=paths or ["/"],
                  checks=[item["id"] for item in checks])
    return result


def validate(config: dict, approval: dict) -> None:
    checks = {item["id"]: item for item in config.get("ownership_checks", [])}
    settings = config.get("role_testing")
    if not checks or not settings or settings["adapter"] != "dtap-cookie-v1":
        raise ToolError("Ownership checks require configured role_testing accounts and ownership_checks entries.")
    if config.get("access") and config["access"]["type"] not in ("iap-browser", "iap-service-account"):
        raise ToolError("Ownership checks support browser or keyless IAP gateway access, not bearer access.")
    if not isinstance(approval, dict) or approval.get("ownership_login") is not True or approval.get("method") != "POST":
        raise ToolError("Ownership checks require explicit ownership_login approval and POST method.")
    head_scope = {key: value for key, value in approval.items() if key not in ("ownership_login", "checks")}
    head_scope["method"] = "HEAD"
    if head_scope.get("exposure_checks"):
        raise ToolError("Ownership and public exposure checks need separate approvals.")
    validate_approval(config, head_scope)
    selected = approval.get("checks")
    if (not isinstance(selected, list) or not 1 <= len(selected) <= 3
            or any(not isinstance(item, str) or item not in checks for item in selected)
            or len(set(selected)) != len(selected)):
        raise ToolError("Approve between one and three distinct configured ownership check IDs.")
    accounts = {item["id"] for item in settings["accounts"]}
    for check_id in selected:
        check = checks[check_id]
        if (check["acting_account"] not in accounts or check["target_account"] not in accounts
                or check["acting_account"] == check["target_account"]):
            raise ToolError(f"Ownership check {check_id!r} needs two distinct configured accounts.")
        if check["write_path"] not in approval["paths"] or check.get("read_path", check["write_path"]) not in approval["paths"]:
            raise ToolError(f"Ownership check {check_id!r} needs its read and write paths in the approved paths.")
    for path in ("/api/auth/signin", "/api/auth/signout"):
        if any(path.startswith(prefix) for prefix in config["scope"]["excluded_prefixes"]):
            raise ToolError("Role sign-in or sign-out is excluded by project scope.")


def dig(value, keys: list[str]):
    for key in keys:
        if not isinstance(value, dict) or key not in value:
            return None
        value = value[key]
    return value


def run(config: dict, approval: dict, output: Path, *, prompt_passwords: bool = False) -> tuple[Path, int]:
    validate(config, approval)
    if output.exists() or not output.parent.is_dir():
        raise ToolError("Output must be a new directory inside an existing private parent.")
    checks = {item["id"]: item for item in config["ownership_checks"]}
    selected = [checks[check_id] for check_id in approval["checks"]]
    needed = sorted({account for check in selected for account in (check["acting_account"], check["target_account"])})
    secrets = role_credentials(config, {**approval, "role_accounts": needed}, prompt_passwords=prompt_passwords)
    validate(config, approval)
    create_output(output)
    started = datetime.now(timezone.utc).isoformat()
    host = urlsplit(config["target"]["url"]).hostname
    expires = utc(approval["expires_at"])
    timeout = approval.get("request_timeout_seconds", 10)
    accounts = {item["id"]: item for item in config["role_testing"]["accounts"]}
    requests_log, errors, cleanup, results = [], [], [], []
    active_path = "/api/auth/signin"
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
        requests_log.append({"method": method, "path": path, "status": status})
        if 300 <= status < 400 or status == 429 or status >= 500:
            stop_cleanup = True
            raise HTTPStop(path, status)
        return status, received, data

    def read_value(path: str, cookies: dict, field: list[str]):
        status, headers, body = call("GET", path, cookies)
        value = json_object(body) if content_class(headers) == "json" else None
        if not 200 <= status < 300 or value is None:
            raise ToolError(f"Could not establish a baseline for {path}; refusing to run the ownership probe.")
        found = dig(value, field)
        if found is None or isinstance(found, (dict, list)):
            raise ToolError(f"Configured read_field for {path} did not resolve to a plain value; "
                            "check the ownership_checks configuration.")
        return found

    def error_record(error):
        kind, message = failure_detail(error)
        if isinstance(error, ToolError) and not isinstance(error, HTTPStop):
            message = str(error)
        errors.append({"path": error.path if isinstance(error, HTTPStop) else active_path,
                       "kind": kind, "message": message[:256]})

    def run_check(check: dict) -> None:
        acting_id, target_id = check["acting_account"], check["target_account"]
        acting, target = accounts[acting_id], accounts[target_id]
        write_path = check["write_path"]
        read_path = check.get("read_path", write_path)
        read_field = check["read_field"]
        probe_field = check["probe_field"]
        id_field = check["id_field"]
        probe_value = f"{PROBE_PREFIX}-{check['id']}-{int(time.time())}"
        record = {"check": check["id"], "acting_account": acting_id, "target_account": target_id,
                  "write_path": write_path, "verdict": "inconclusive"}
        results.append(record)
        target_session, acting_session = {}, {}
        target_user_id, baseline, restored = None, None, False
        acting_user_id, acting_baseline, acting_restored = None, None, True

        def write_as(session, target_user_id_value, value):
            status, headers, body = call("PUT" if check.get("write_method", "PUT").upper() == "PUT" else "PATCH",
                                         write_path, session,
                                         body=json.dumps({id_field: target_user_id_value, probe_field: value}).encode())
            return 200 <= status < 300

        try:
            target_identity = sign_in(call, secrets, target_id, target, host, target_session)
            target_user_id = dig(target_identity, ["user", "id"])
            if not isinstance(target_user_id, str) or not target_user_id:
                raise ToolError(f"Login response for {target_id} did not include a usable user id.")
            baseline = read_value(read_path, target_session, read_field)
            if isinstance(baseline, str) and baseline.startswith(PROBE_PREFIX):
                raise ToolError(f"{target_id}'s {probe_field} already looks like a leftover probe value; "
                                "restore it manually before running this check again.")

            try:
                acting_identity = sign_in(call, secrets, acting_id, acting, host, acting_session)
                acting_user_id = dig(acting_identity, ["user", "id"])
                # Read the actor's own value too: if a properly scoped endpoint instead writes to the actor's own
                # record, that still needs restoring, and it is the evidence that distinguishes "fixed" from
                # "accepted the request but nothing changed anywhere" (which stays ambiguous).
                acting_baseline = read_value(read_path, acting_session, read_field) if acting_user_id else None
                probe_accepted = write_as(acting_session, target_user_id, probe_value)
                after_acting = (read_value(read_path, acting_session, read_field)
                                if probe_accepted and acting_baseline is not None else acting_baseline)
                acting_changed = after_acting == probe_value
                if acting_changed:
                    acting_restored = write_as(acting_session, acting_user_id, acting_baseline)
            finally:
                sign_out(call, acting_id, acting_session, cleanup, error_record, stop_cleanup)
                acting_session.clear()
            after = read_value(read_path, target_session, read_field) if probe_accepted else baseline
            changed = after == probe_value
            if changed:
                record["verdict"] = "confirmed"
            elif not probe_accepted or acting_changed:
                record["verdict"] = "not_reproduced"
            else:
                record["verdict"] = "suspected"
            record["detail"] = (
                f"{acting_id} wrote to {target_id}'s record ({target_user_id[:8]}...) and the change was "
                f"verified by re-reading it as {target_id}."
                if changed else
                f"The write was scoped to {acting_id}'s own record (verified by re-reading it), not {target_id}'s; "
                f"the id in the request body was ignored."
                if acting_changed else
                f"{acting_id}'s write to {target_id}'s record was rejected."
                if not probe_accepted else
                f"{acting_id}'s write to {target_id}'s record returned success, but neither {target_id}'s nor "
                f"{acting_id}'s own record changed when re-read; the write may have gone elsewhere."
            )
        finally:
            if target_user_id is not None and baseline is not None:
                try:
                    write_as(target_session, target_user_id, baseline)
                    restored = True
                except (ToolError, OSError, http.client.HTTPException) as error:
                    error_record(error)
            record["restored"] = restored and acting_restored
            sign_out(call, target_id, target_session, cleanup, error_record, stop_cleanup)
            target_session.clear()

    try:
        if config.get("access", {}).get("type") == "iap-service-account":
            gateway_session = ServiceAccountAccess(config, approval, validate_scope=validate)
        elif config.get("access"):
            gateway_headers = browser_login(config, approval, validate_scope=validate)
        for check in selected:
            run_check(check)
            if errors:
                break
    except (ToolError, OSError, http.client.HTTPException) as error:
        error_record(error)
    finally:
        if gateway_session:
            gateway_session.clear()
        gateway_headers.clear()
        secrets.clear()

    findings = []
    for record in results:
        if record["verdict"] not in ("confirmed", "suspected"):
            continue
        findings.append({
            "title": f"{record['acting_account']} can change {record['target_account']}'s record",
            "severity": "high" if record["verdict"] == "confirmed" else "medium",
            "verification": record["verdict"],
            "category": "unauthorized_access", "owasp": "A01", "path": record["write_path"],
            "impact": f"A write to {record['write_path']} using another user's id reached that user's own record. "
                      + record["detail"],
            "remediation": "Take the record's owner from the signed-in session, not from request input; compare an "
                           "explicit id against the session before writing.",
            "evidence": record["detail"] + (" The probed value was restored." if record["restored"]
                                            else " RESTORE FAILED: check the record manually."),
        })
    if any(not record.get("restored") for record in results):
        errors.append({"path": "/", "kind": "scope",
                       "message": "A probed value could not be confirmed restored; check the affected record(s) manually."})
    if len(results) != len(selected) and not errors:
        errors.append({"path": "/", "kind": "scope", "message": "Not every approved ownership check completed."})
    result = {
        "schema_version": 1, "project": config["project"], "target": config["target"]["url"],
        "started_at": started, "finished_at": datetime.now(timezone.utc).isoformat(),
        "status": "incomplete" if errors else "completed", "profile": "dtap-ownership-probe",
        "scope_sha256": digest(approval), "approved_paths": approval["paths"],
        "observations": [], "findings": findings, "errors": errors[:100], "requests": requests_log,
        "ownership_checks": approval["checks"], "ownership_results": results, "ownership_cleanup": cleanup,
        "coverage": {"data_exposure": "not_tested",
                     "unauthorized_access": "tested" if not errors else "not_tested",
                     "note": "Each configured check reads the target account's own current value, has the acting "
                             "account attempt to overwrite it using the target's id, re-reads it as the target to "
                             "confirm whether it changed, and restores the original value immediately regardless "
                             "of outcome. This exercises exactly one write per check per account; it does not "
                             "explore other ownership-sensitive fields or endpoints. A write that is accepted "
                             "(HTTP 2xx) but does not change the re-read value is reported only as suspected."},
    }
    destination = output / "assessment.json"
    write_private(destination, json.dumps(result, indent=2))
    return destination, 1 if errors else 0
