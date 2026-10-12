"""Read-only staging checks: header/cookie observations and a short exposed-file list, never attack payloads."""
import json
import os
import re
import sys
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import yaml

from .assessment import approval_template, assess
from .process import ToolError

RUN_WINDOW = timedelta(hours=1)


class NotCovered(ToolError):
    """The live check couldn't look at the target at all, so it's a coverage gap rather than a finding."""


class Partial(ToolError):
    """The live check ran but covered too little to call it done."""


# One path per approval: the runner stops a run at the first 401/403/redirect (a safety rule we keep), and for a
# regression check that status is the answer being measured, so each check gets its own run.
PATHS_PER_APPROVAL = 1
HTTP_STATUS = re.compile(r"HTTP (\d{3})")


def regressions_path(config_path: Path) -> Path:
    return config_path.with_name(config_path.name.replace(".vapt.yml", ".regressions.yml"))


def regression_checks(config_path: Path | None) -> list[dict]:
    """Past findings to re-check on every live scan: [{name, path, expect: [status, ...]}]."""
    if config_path is None or not regressions_path(config_path).is_file():
        return []
    data = yaml.safe_load(regressions_path(config_path).read_text()) or {}
    checks = []
    for item in data.get("checks", []):
        path, expect = item.get("path"), item.get("expect_status")
        if not isinstance(path, str) or not path.startswith("/") or not expect:
            raise ToolError(f"{regressions_path(config_path).name}: every check needs a path and expect_status.")
        checks.append({"name": item.get("name", path), "path": path,
                       "expect": expect if isinstance(expect, list) else [expect]})
    return checks


def browser_sign_in_possible() -> bool:
    """IAP browser sign-in needs a desktop; automated runs (CI, SSH without a display) can't do it."""
    if os.environ.get("CI"):
        return False
    return sys.platform != "linux" or bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))


def standing_approval_path(config_path: Path) -> Path:
    return config_path.with_name(config_path.name.replace(".vapt.yml", ".standing-approval.yml"))


def standing_approval(config_path: Path | None) -> dict | None:
    """The owner's standing approval for automatic read-only checks of this project, or None if there is none.

    Returns the record with an "active" flag; an expired approval is returned inactive so callers can say so.
    """
    if config_path is None:
        return None
    path = standing_approval_path(config_path)
    if not path.is_file():
        return None
    record = yaml.safe_load(path.read_text())
    if (not isinstance(record, dict) or not isinstance(record.get("approved_by"), str)
            or not record["approved_by"].strip() or not isinstance(record.get("expires_on"), date)):
        raise ToolError(f"{path.name} needs approved_by and expires_on (YYYY-MM-DD).")
    return {**record, "active": date.today() <= record["expires_on"]}


def run_read_only(config: dict, standing: dict, output: Path, paths: list[str] | None = None) -> dict:
    """Run the existing read-only checks under a fresh one-hour approval derived from the standing approval."""
    if not standing.get("active"):
        raise ToolError("The standing approval has expired.")
    now = datetime.now(timezone.utc)
    approval = approval_template(config)
    approval.update({
        "approved_by": standing["approved_by"],
        "starts_at": now.isoformat(),
        "expires_at": (now + RUN_WINDOW).isoformat(),
        # Exposure checks are only allowed against unauthenticated targets; behind IAP, headers only.
        "exposure_checks": not config.get("access") and paths is None,
        "paths": paths or ["/"],
    })
    path, _ = assess(config, approval, output)
    return json.loads(path.read_text())


def run_regressions(config: dict, standing: dict, checks: list[dict], output: Path) -> list[dict]:
    """Request each regression path (HEAD, read-only) and compare its status with the expected one."""
    results = []
    for index in range(0, len(checks), PATHS_PER_APPROVAL):
        batch = checks[index:index + PATHS_PER_APPROVAL]
        result = run_read_only(config, standing, output.with_name(f"{output.name}-{index // PATHS_PER_APPROVAL + 1}"),
                               paths=[check["path"] for check in batch])
        statuses = {item["path"]: item.get("status") for item in result.get("observations", [])}
        errors = {item["path"]: item.get("message") for item in result.get("errors", [])}
        for check in batch:
            status = statuses.get(check["path"])
            stopped = HTTP_STATUS.search(errors.get(check["path"]) or "")
            if status is None and stopped:
                status = int(stopped[1])
            results.append({**check, "status": status, "error": errors.get(check["path"]),
                            "ok": status in check["expect"]})
    return results


def staging_counts(result: dict) -> dict:
    return {
        "confirmed": sum(item["verification"] == "confirmed" for item in result["findings"]),
        "suspected": sum(item["verification"] == "suspected" for item in result["findings"]),
        "exposed": sum(bool(item.get("exposed")) for item in result.get("exposure", [])),
        "errors": len(result["errors"]),
    }


def staging_recap(result: dict) -> str:
    counts = staging_counts(result)
    parts = []
    if counts["confirmed"]:
        parts.append(f"{counts['confirmed']} confirmed header/cookie issues")
    if counts["suspected"]:
        parts.append(f"{counts['suspected']} suspected header/cookie issues")
    if counts["exposed"]:
        parts.append(f"{counts['exposed']} exposed files or endpoints")
    if counts["errors"]:
        parts.append(f"{counts['errors']} requests that did not complete")
    if not parts:
        return "Nothing was flagged on the pages checked. This only covered headers, cookies and a short exposure list, not a full test."
    text = "Found " + (parts[0] if len(parts) == 1 else ", ".join(parts[:-1]) + " and " + parts[-1]) + "."
    if counts["exposed"]:
        text += " Next, open assessment.json's exposure section and confirm each exposed path, then restrict or remove it."
    elif counts["confirmed"]:
        text += " Next, fix the confirmed header/cookie issues; they were observed twice."
    elif counts["suspected"]:
        text += " Next, review the suspected findings; they were only observed once."
    recon = result.get("recon")
    if recon:
        notes = []
        if recon["subdomains"]:
            notes.append(f"{len(recon['subdomains'])} subdomain(s) found in certificate logs")
        if not recon["dns"]["dmarc_present"]:
            notes.append("no DMARC record")
        if recon["technologies"]:
            notes.append("detected: " + ", ".join(recon["technologies"]))
        if recon["open_ports"]:
            notes.append(f"open ports: {', '.join(str(port) for port in recon['open_ports'])}")
        if recon.get("discovered_paths"):
            notes.append(f"{len(recon['discovered_paths'])} path(s) found in robots.txt/sitemap.xml")
        tls = recon.get("tls")
        if tls and tls["legacy_protocols_supported"]:
            notes.append("legacy TLS still accepted: " + ", ".join(tls["legacy_protocols_supported"]))
        if tls and tls["cert_days_to_expiry"] is not None and tls["cert_days_to_expiry"] < 30:
            notes.append(f"certificate expires in {tls['cert_days_to_expiry']} day(s)")
        if notes:
            text += " Recon: " + "; ".join(notes) + "."
    return text
