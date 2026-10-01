"""Single-operator localhost dashboard. No Docker socket, uploads or implicit live scans."""
import atexit
import hmac
import json
import os
import re
import secrets
import shutil
import signal
import subprocess
import sys
import threading
import uuid
from datetime import datetime, timedelta, timezone
from importlib.resources import files
from pathlib import Path

from flask import Flask, jsonify, request as http_request, send_file

from .assessment import approval_template, create_output, digest, load_json, utc, validate_approval, write_private
from .config import ConfigError, load_config
from .doctor import browser_check
from .process import ToolError
from .roles import credentials, role_outcome, template as role_template, validate as validate_roles

JOB_ID = re.compile(r"[a-f0-9]{32}")
PROJECT_ID = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,100}\.ya?ml")
EXPORTS = {"html": "report/report.html", "pdf": "report/report.pdf",
           "json": "assessment/assessment.json"}


class Jobs:
    def __init__(self, root: Path):
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        root.chmod(0o700)
        self.root = root
        self.lock = threading.Lock()
        self.active = None
        self.process = None

    def launch(self, spec: dict) -> str:
        with self.lock:
            if self.active:
                raise ToolError("Another run is active. Wait for it to finish before starting another.")
            identifier = uuid.uuid4().hex
            output = self.root / identifier
            create_output(output)
            metadata = {"id": identifier, "profile": spec["profile"],
                        "project": spec.get("config", {}).get("project", "demonstration"),
                        "created_at": datetime.now(timezone.utc).isoformat()}
            write_private(output / "job.json", json.dumps(metadata))
            self.active = identifier
            thread = threading.Thread(target=self.work, args=(identifier, spec), daemon=True)
            thread.start()
            return identifier

    def work(self, identifier, spec):
        output = self.root / identifier
        outcome = None
        try:
            with self.lock:
                self.process = subprocess.Popen(
                    [sys.executable, "-m", "vaptkit.dashboard_worker", str(output)],
                    stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    start_new_session=True,
                )
                process = self.process
            seconds = 120 if spec["profile"] == "demo" else 30 * 60 + 120
            try:
                process.communicate(json.dumps(spec).encode(), timeout=seconds)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.communicate()
                outcome = {"status": "failed", "message": "Run timed out. Inspect partial evidence; live sessions may need manual cleanup."}
            if process.returncode and not (output / "outcome.json").exists() and outcome is None:
                outcome = {"status": "failed", "message": "Worker stopped unexpectedly. Inspect partial evidence; session cleanup is unconfirmed."}
        except OSError:
            outcome = {"status": "failed", "message": "Worker could not start or finish; check local resources."}
        finally:
            spec.get("credentials", {}).clear()
            try:
                if outcome is not None and not (output / "outcome.json").exists():
                    write_private(output / "outcome.json", json.dumps(outcome))
            finally:
                with self.lock:
                    self.active = None
                    self.process = None

    def close(self):
        with self.lock:
            if self.process and self.process.poll() is None:
                os.killpg(self.process.pid, signal.SIGTERM)

    def result(self, identifier: str) -> dict:
        if not JOB_ID.fullmatch(identifier):
            raise ToolError("Invalid run identifier.")
        root = self.root / identifier
        if not (root / "job.json").is_file():
            raise ToolError("Run was not found.")
        result = load_json(root / "job.json")
        result["status"] = "running" if self.active == identifier else "interrupted"
        result["message"] = ("Working within the approved scope." if result["status"] == "running"
                             else "Run interrupted. Review partial evidence; live sessions may require manual cleanup.")
        if (root / "outcome.json").is_file():
            result.update(load_json(root / "outcome.json"))
        source = root / "assessment/assessment.json"
        if source.is_file():
            assessment = load_json(source)
            from .report import validate_result
            validate_result(assessment)
            result["assessment_status"] = assessment["status"]
            result["findings"] = assessment["findings"]
            result["errors"] = assessment["errors"]
            result["coverage"] = assessment["coverage"]
            result["cleanup"] = assessment.get("role_cleanup", [])
            records = assessment.get("role_observations", [])
            controls = {item["path"] for item in records if role_outcome(item, set()) == "allowed"}
            result["cells"] = [{"account": item["account"], "path": item["path"],
                                "outcome": role_outcome(item, controls)} for item in records]
            result["expected_cells"] = len(assessment.get("role_accounts", [])) * len(assessment["approved_paths"])
        result["downloads"] = [name for name, path in EXPORTS.items() if (root / path).is_file()]
        return result


def create_app(projects: Path, data: Path, *, origin="http://127.0.0.1:8765") -> Flask:
    if not re.fullmatch(r"http://(?:127\.0\.0\.1|localhost):[0-9]{1,5}", origin):
        raise ToolError("Dashboard origin must be an explicit localhost HTTP URL.")
    app = Flask(__name__, static_folder=None)
    app.config.update(MAX_CONTENT_LENGTH=65536, PROPAGATE_EXCEPTIONS=False)
    token = secrets.token_urlsafe(32)
    assets = files("vaptkit").joinpath("assets/dashboard")
    jobs = Jobs(data)
    app.extensions["jobs"] = jobs
    atexit.register(jobs.close)

    @app.before_request
    def local_boundary():
        if http_request.host != origin.removeprefix("http://"):
            return jsonify(error="Use the configured localhost URL."), 403
        if http_request.headers.get("Sec-Fetch-Site") not in (None, "same-origin", "none"):
            return jsonify(error="Cross-site requests are not permitted."), 403
        if http_request.path.startswith("/api/"):
            supplied = http_request.headers.get("X-MVK-Token", "")
            if not hmac.compare_digest(supplied.encode(), token.encode()):
                return jsonify(error="Dashboard session expired. Reload this page."), 403
            if http_request.method != "GET" and http_request.headers.get("Origin") != origin:
                return jsonify(error="Same-origin browser access is required."), 403

    @app.after_request
    def headers(response):
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; script-src 'self'; style-src 'self'; "
            "connect-src 'self'; img-src 'self' data:; font-src 'self'; "
            "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
        )
        return response

    @app.errorhandler(ToolError)
    @app.errorhandler(ConfigError)
    def expected_error(error):
        return jsonify(error=str(error)), 400

    @app.errorhandler(413)
    def too_large(error):
        return jsonify(error="Input is too large; use at most 64 KiB."), 413

    @app.errorhandler(400)
    def malformed(error):
        return jsonify(error="Invalid request body; values withheld."), 400

    @app.errorhandler(415)
    def unsupported_body(error):
        return jsonify(error="Use a JSON request body."), 415

    def body():
        value = http_request.get_json()
        if not isinstance(value, dict):
            raise ToolError("A JSON object is required.")
        return value

    def project(identifier):
        if not isinstance(identifier, str) or not PROJECT_ID.fullmatch(identifier):
            raise ToolError("Select a configured project.")
        path = projects / identifier
        if path.is_symlink() or not path.is_file():
            raise ToolError("Project file is unavailable or symlinked.")
        return load_config(path)

    def supported(config, profile):
        if profile not in ("headers", "roles"):
            raise ToolError("Choose a supported assessment profile.")
        access = config.get("access", {}).get("type")
        if access not in (None, "iap-service-account"):
            raise ToolError("This dashboard supports public or keyless IAP access. Use the CLI for interactive IAP or bearer access.")
        if profile == "roles" and not config.get("role_testing"):
            raise ToolError("This project has no configured role adapter.")
        if access == "iap-service-account":
            try:
                available = shutil.which("gcloud") is not None and Path("/gcloud-source/credentials.db").is_file()
            except OSError:
                available = False
            if not available:
                raise ToolError("Keyless IAP requires gcloud and a readable optional credential mount. See dashboard setup.")

    @app.get("/")
    def index():
        return assets.joinpath("index.html").read_text().replace("__MVK_TOKEN__", token), 200, {"Content-Type": "text/html; charset=utf-8"}

    @app.get("/assets/<name>")
    def asset(name):
        if name not in ("app.js", "style.css"):
            return "", 404
        mime = "text/javascript" if name.endswith(".js") else "text/css"
        return assets.joinpath(name).read_text(), 200, {"Content-Type": mime}

    @app.get("/health")
    def health():
        return jsonify(status="ready")

    @app.get("/api/projects")
    def list_projects():
        rows = []
        for path in sorted(projects.glob("*"))[:100]:
            if not PROJECT_ID.fullmatch(path.name):
                continue
            try:
                config = project(path.name)
            except (ConfigError, ToolError):
                rows.append({"id": path.name, "error": "Invalid project configuration; fix the mounted YAML."})
                continue
            rows.append({
                "id": path.name, "name": config["project"], "target": config["target"]["url"],
                "digest": digest(config), "access": config.get("access", {}).get("type", "public"),
                "accounts": [{"id": item["id"], "role": item["role"]} for item in
                             config.get("role_testing", {}).get("accounts", [])],
                "routes": config.get("role_testing", {}).get("routes", []),
            })
        return jsonify(projects=rows, origin=origin)

    @app.post("/api/preview")
    def preview():
        value = body()
        config = project(value.get("project"))
        profile = value.get("profile")
        supported(config, profile)
        if value.get("digest") != digest(config):
            raise ToolError("Project changed. Reload the project list before approving.")
        owner = value.get("owner")
        if not isinstance(owner, str) or not owner.strip() or len(owner) > 120 or any(ord(c) < 32 for c in owner):
            raise ToolError("Enter the authorized owner's name (up to 120 printable characters).")
        minutes = value.get("minutes", 10)
        if type(minutes) is not int or not 1 <= minutes <= 30:
            raise ToolError("Choose a window between 1 and 30 minutes.")
        now = datetime.now(timezone.utc)
        approval = role_template(config) if profile == "roles" else approval_template(config)
        approval.update(approved_by=owner, starts_at=now.isoformat(),
                        expires_at=(now + timedelta(minutes=minutes)).isoformat(),
                        paths=value.get("paths"), interval_seconds=2, request_timeout_seconds=20)
        fields = []
        if profile == "roles":
            approval.update(role_accounts=value.get("accounts"), role_login=True)
            validate_roles(config, approval)
            for item in config["role_testing"]["accounts"]:
                if item["id"] in approval["role_accounts"]:
                    for key, kind in (("email_env", "email"), ("password_env", "password")):
                        if not any(field["name"] == item[key] for field in fields):
                            fields.append({"name": item[key], "kind": kind})
        else:
            validate_approval(config, approval)
        ready, detail = browser_check(headless=True)
        if not ready:
            raise ToolError(detail)
        maximum = (2 * len(approval["paths"]) if profile == "headers" else
                   2 * (len(approval["role_accounts"]) + 1) * len(approval["paths"]) + 2 * len(approval["role_accounts"]))
        return jsonify(approval=approval, fields=fields, maximum_requests=maximum,
                       target=config["target"]["url"], digest=digest(config))

    @app.post("/api/jobs")
    def launch():
        value = body()
        if value.get("acknowledge") is not True:
            raise ToolError("Explicit approval and artifact-review acknowledgement are required.")
        profile = value.get("profile")
        if profile == "demo":
            if set(value) != {"profile", "acknowledge"}:
                raise ToolError("The demo accepts no project, target or credentials.")
            return jsonify(id=jobs.launch({"profile": "demo"})), 202
        if set(value) != {"profile", "project", "approval", "credentials", "acknowledge"}:
            raise ToolError("Run fields do not match the dashboard form.")
        config = project(value.get("project"))
        supported(config, profile)
        approval = value.get("approval")
        (validate_roles if profile == "roles" else validate_approval)(config, approval)
        if (approval.get("exposure_checks") or approval["interval_seconds"] != 2
                or approval.get("request_timeout_seconds") != 20
                or (utc(approval["expires_at"]) - utc(approval["starts_at"])).total_seconds() > 1800):
            raise ToolError("Dashboard approval must use its bounded preview settings.")
        values = value.get("credentials", {})
        if not isinstance(values, dict):
            raise ToolError("Credential input must be an object.")
        allowed = {item[field] for item in config.get("role_testing", {}).get("accounts", [])
                   if item["id"] in approval.get("role_accounts", []) for field in ("email_env", "password_env")}
        if set(values) != allowed:
            raise ToolError("Supply exactly the credential fields for the approved accounts.")
        if profile == "roles":
            credentials(config, approval, values=values).clear()
        spec = {"profile": profile, "config": config, "approval": approval, "credentials": dict(values)}
        return jsonify(id=jobs.launch(spec)), 202

    @app.get("/api/jobs")
    def history():
        identifiers = sorted(
            (path for path in data.iterdir() if path.is_dir() and JOB_ID.fullmatch(path.name)),
            key=lambda path: path.stat().st_mtime, reverse=True,
        )[:30]
        return jsonify(jobs=[jobs.result(path.name) for path in identifiers])

    @app.get("/api/jobs/<identifier>")
    def result(identifier):
        return jsonify(jobs.result(identifier))

    @app.get("/api/jobs/<identifier>/download/<kind>")
    def download(identifier, kind):
        result = jobs.result(identifier)
        if kind not in result["downloads"] or kind not in EXPORTS:
            raise ToolError("This artifact is not available.")
        return send_file(data / identifier / EXPORTS[kind], as_attachment=True,
                         download_name=f"mvk-{identifier[:8]}.{ 'json' if kind == 'json' else kind}")

    return app


def main():
    from waitress import serve
    origin = os.environ.get("MVK_DASHBOARD_ORIGIN", "http://127.0.0.1:8765")
    projects = Path(os.environ.get("MVK_PROJECTS_DIR", "projects")).resolve()
    data = Path(os.environ.get("MVK_DATA_DIR", ".private/dashboard")).resolve()
    app = create_app(projects, data, origin=origin)
    def stop(signum, frame):
        app.extensions["jobs"].close()
        raise SystemExit(0)
    signal.signal(signal.SIGTERM, stop)
    print(f"Matt VAPT Kit dashboard: {origin}", flush=True)
    print("Local single-operator use only. No assessment starts automatically.", flush=True)
    serve(app, host=os.environ.get("MVK_LISTEN_HOST", "127.0.0.1"), port=8765, threads=4,
          max_request_body_size=65536, channel_timeout=30)


if __name__ == "__main__":
    main()
