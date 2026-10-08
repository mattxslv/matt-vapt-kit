"""Read-only staging checks: header/cookie observations and a short exposed-file list, never attack payloads."""
import json
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import yaml

from .assessment import approval_template, assess
from .process import ToolError

RUN_WINDOW = timedelta(hours=1)


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


def run_read_only(config: dict, standing: dict, output: Path) -> dict:
    """Run the existing read-only checks under a fresh one-hour approval derived from the standing approval."""
    if not standing.get("active"):
        raise ToolError("The standing approval has expired.")
    now = datetime.now(timezone.utc)
    approval = approval_template(config)
    approval.update({
        "approved_by": standing["approved_by"],
        "starts_at": now.isoformat(),
        "expires_at": (now + RUN_WINDOW).isoformat(),
        "exposure_checks": True,
        "paths": ["/"],
    })
    path, _ = assess(config, approval, output)
    return json.loads(path.read_text())


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
    return text
