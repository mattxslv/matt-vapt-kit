"""One disposable process per dashboard job. Secrets arrive through stdin, never argv or files."""
import contextlib
import io
import json
import os
import shutil
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from .assessment import assess, create_output, digest, load_json, write_private
from .process import ToolError
from .report import generate, validate_result
from .roles import run as run_roles


def demo(root: Path):
    now = datetime.now(timezone.utc).isoformat()
    result = {
        "schema_version": 1, "project": "demonstration", "target": "https://staging.example.invalid",
        "started_at": now, "finished_at": now, "status": "fixture",
        "profile": "unauthenticated-head-only", "scope_sha256": "0" * 64,
        "approved_paths": ["/"], "errors": [],
        "observations": [{"path": "/", "method": "HEAD", "status": 200, "checks": {
            "html_response": True, "hsts_present": True, "csp_present": False,
            "nosniff": True, "frame_policy_present": True,
        }}],
        "findings": [{
            "title": "Example: Content Security Policy not observed", "severity": "low",
            "verification": "observation", "category": "configuration", "path": "/",
            "impact": "This is synthetic evidence to demonstrate report interpretation. No live request was sent.",
            "remediation": "For a real system, review the application policy and verify it in an approved assessment.",
        }],
        "coverage": {"data_exposure": "not_tested", "unauthorized_access": "not_tested",
                     "note": "Synthetic demonstration only. No live target was contacted and no security assessment was performed."},
    }
    create_output(root / "assessment")
    write_private(root / "assessment/assessment.json", json.dumps(result, indent=2))


def prepare_gcloud(directory: Path):
    source = Path("/gcloud-source")
    if not source.is_dir():
        raise ToolError("Keyless access requires the optional read-only gcloud mount. See dashboard setup.")
    target = directory / "gcloud"
    target.mkdir(mode=0o700)
    # Copy only CLI identity/config files. Logs and unrelated application credentials are not copied.
    for name in ("credentials.db", "access_tokens.db", "active_config"):
        path = source / name
        if path.is_symlink():
            raise ToolError("Symlinked cloud credential files are not supported.")
        if path.is_file():
            shutil.copyfile(path, target / name)
            (target / name).chmod(0o600)
    configs = source / "configurations"
    if configs.is_dir() and not configs.is_symlink():
        (target / "configurations").mkdir(mode=0o700)
        for path in configs.glob("config_*"):
            if path.is_file() and not path.is_symlink():
                shutil.copyfile(path, target / "configurations" / path.name)
                (target / "configurations" / path.name).chmod(0o600)
    if not (target / "credentials.db").is_file():
        raise ToolError("No gcloud user credential database is available in the optional mount.")
    os.environ["CLOUDSDK_CONFIG"] = str(target)
    os.environ["CLOUDSDK_CORE_DISABLE_USAGE_REPORTING"] = "true"
    os.environ["CLOUDSDK_CORE_LOG_HTTP"] = "false"


def execute(spec: dict, root: Path):
    config = spec.get("config")
    with tempfile.TemporaryDirectory(prefix="mvk-job-") as temporary:
        if config and config.get("access", {}).get("type") == "iap-service-account":
            prepare_gcloud(Path(temporary))
        if spec["profile"] == "demo":
            demo(root)
        else:
            if digest(config) != spec["approval"]["config_sha256"]:
                raise ToolError("Project configuration changed after approval.")
            write_private(root / "approval.json", json.dumps(spec["approval"], indent=2))
            if spec["profile"] == "roles":
                run_roles(config, spec["approval"], root / "assessment",
                          credential_values=spec["credentials"])
            else:
                assess(config, spec["approval"], root / "assessment")
        spec.get("credentials", {}).clear()
        result = load_json(root / "assessment/assessment.json")
        validate_result(result)
        generate(root / "assessment/assessment.json", root / "report", reviewed=True)
        return {"status": "completed", "assessment_status": result["status"],
                "message": "Demo report ready. No live scan was run." if spec["profile"] == "demo"
                else "Assessment finished. Review findings, coverage gaps and session cleanup."}


def main():
    os.umask(0o077)
    root = Path(sys.argv[1])
    spec = {}
    try:
        raw = sys.stdin.buffer.read(65537)
        if len(raw) > 65536:
            raise ToolError("Job input exceeds the limit.")
        spec = json.loads(raw)
        del raw
        # Existing adapters may print operational messages. Never relay their raw output to HTTP clients.
        with contextlib.redirect_stdout(io.StringIO()):
            outcome = execute(spec, root)
    except ToolError as error:
        outcome = {"status": "failed", "message": str(error)[:256]}
    except (OSError, ValueError, KeyError, TypeError):
        outcome = {"status": "failed", "message": "The assessment or report export failed; raw details withheld."}
    finally:
        spec.get("credentials", {}).clear()
    write_private(root / "outcome.json", json.dumps(outcome))
    return 0 if outcome["status"] == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
