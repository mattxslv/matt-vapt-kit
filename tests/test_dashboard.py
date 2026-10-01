import copy
import importlib.util
import json
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

from test_roles import Application, ENV, approval_for, configuration
from vaptkit.assessment import create_output, digest, load_json, write_private
from vaptkit.process import ToolError

HAS_FLASK = importlib.util.find_spec("flask") is not None


@unittest.skipUnless(HAS_FLASK, "dashboard extra required")
class DashboardTests(unittest.TestCase):
    def setUp(self):
        from vaptkit.dashboard import create_app
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.projects = self.root / "projects"
        self.projects.mkdir()
        self.config = configuration()
        self.config["target"].update(url="https://staging.example.invalid", allowed_hosts=["staging.example.invalid"])
        (self.projects / "fixture.yml").write_text(yaml.safe_dump(self.config))
        self.app = create_app(self.projects, self.root / "data")
        self.app.testing = True
        self.client = self.app.test_client()
        self.origin = "http://127.0.0.1:8765"
        response = self.client.get("/", base_url=self.origin)
        self.token = re.search(r'name="mvk-token" content="([^"]+)"', response.text)[1]
        self.headers = {"X-MVK-Token": self.token, "Origin": self.origin}
        self.jobs = self.app.extensions["jobs"]
        self.addCleanup(self.jobs.close)

    def get(self, path):
        return self.client.get(path, headers=self.headers, base_url=self.origin)

    def post(self, path, value):
        return self.client.post(path, json=value, headers=self.headers, base_url=self.origin)

    def preview(self, profile="roles"):
        value = {"project": "fixture.yml", "profile": profile, "digest": digest(self.config),
                 "owner": "Synthetic owner", "minutes": 10,
                 "paths": [self.config["role_testing"]["routes"][0]["path"]],
                 "accounts": ["service-provider", "lead-evaluator"]}
        with patch("vaptkit.dashboard.browser_check", return_value=(True, "Ready")):
            return self.post("/api/preview", value)

    def test_local_host_origin_csrf_and_fetch_site_boundaries(self):
        self.assertEqual(self.client.get("/api/projects", base_url=self.origin).status_code, 403)
        self.assertEqual(self.client.get("/api/projects", base_url=self.origin,
                                        headers={"X-MVK-Token": "invalid-\u00e9"}).status_code, 403)
        self.assertEqual(self.client.get("/", base_url="http://evil.invalid:8765").status_code, 403)
        self.assertEqual(self.client.get("/", base_url=self.origin,
                                        headers={"Sec-Fetch-Site": "cross-site"}).status_code, 403)
        bad = dict(self.headers, Origin="https://evil.invalid")
        self.assertEqual(self.client.post("/api/jobs", base_url=self.origin, headers=bad,
                                         json={"profile": "demo", "acknowledge": True}).status_code, 403)
        response = self.get("/api/projects")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        self.assertIn("frame-ancestors 'none'", response.headers["Content-Security-Policy"])
        self.assertNotIn("Access-Control-Allow-Origin", response.headers)

    def test_no_target_requests_or_credentials_for_project_listing(self):
        with patch("socket.socket", side_effect=AssertionError("No network allowed")), patch.dict(os.environ, ENV):
            response = self.get("/api/projects")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.json["projects"]), 1)
        for value in ENV.values():
            self.assertNotIn(value, response.text)

    def test_preview_is_bounded_and_does_not_launch(self):
        with patch.object(self.jobs, "launch") as launch:
            response = self.preview()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["maximum_requests"], 10)
        self.assertEqual(len(response.json["fields"]), 3)
        self.assertTrue(response.json["approval"]["role_login"])
        launch.assert_not_called()
        self.assertEqual(list((self.root / "data").iterdir()), [])

    def test_missing_control_digest_and_unsupported_gateway_rejected(self):
        value = {"project": "fixture.yml", "profile": "roles", "owner": "Synthetic owner",
                 "digest": digest(self.config), "paths": [self.config["role_testing"]["routes"][0]["path"]],
                 "accounts": ["service-provider"], "minutes": 10}
        self.assertEqual(self.post("/api/preview", value).status_code, 400)
        value.update(profile="headers", digest="0" * 64)
        self.assertEqual(self.post("/api/preview", value).status_code, 400)
        self.config["access"] = {"type": "iap-browser"}
        (self.projects / "fixture.yml").write_text(yaml.safe_dump(self.config))
        value["digest"] = digest(self.config)
        self.assertEqual(self.post("/api/preview", value).status_code, 400)

    def test_role_job_validates_approval_and_only_selected_credentials(self):
        approval = self.preview().json["approval"]
        spec = {"profile": "roles", "project": "fixture.yml", "approval": approval,
                "credentials": dict(ENV), "acknowledge": True}
        with patch.object(self.jobs, "launch", return_value="a" * 32) as launch:
            response = self.post("/api/jobs", spec)
        self.assertEqual(response.status_code, 202)
        self.assertEqual(launch.call_args.args[0]["credentials"], ENV)
        for mutate in (
            lambda value: value.update(acknowledge=False),
            lambda value: value["approval"].update(config_sha256="0" * 64),
            lambda value: value["credentials"].update(PATH="PRIVATE_SENTINEL"),
            lambda value: value["credentials"].update(DTAP_QA_PASSWORD=42),
            lambda value: value["approval"].update(expires_at="2000-01-01T00:00:00Z"),
        ):
            value = copy.deepcopy(spec)
            mutate(value)
            with patch.object(self.jobs, "launch") as launch:
                response = self.post("/api/jobs", value)
            self.assertEqual(response.status_code, 400)
            self.assertNotIn("PRIVATE_SENTINEL", response.text)
            launch.assert_not_called()

    def test_demo_rejects_live_parameters_and_duplicate_busy_run(self):
        with patch.object(self.jobs, "launch", return_value="a" * 32) as launch:
            response = self.post("/api/jobs", {"profile": "demo", "acknowledge": True})
            self.assertEqual(response.status_code, 202)
            self.assertEqual(launch.call_args.args[0], {"profile": "demo"})
            response = self.post("/api/jobs", {"profile": "demo", "acknowledge": True, "target": "https://example.com"})
            self.assertEqual(response.status_code, 400)
        self.jobs.active = "a" * 32
        with self.assertRaises(ToolError):
            self.jobs.launch({"profile": "demo"})
        self.jobs.active = None

    def test_interrupted_run_and_download_allowlist(self):
        identifier = "b" * 32
        root = self.root / "data" / identifier
        create_output(root)
        write_private(root / "job.json", json.dumps({"id": identifier, "profile": "roles", "project": "fixture",
                                                   "created_at": "2026-10-01T00:00:00Z"}))
        write_private(root / "approval.json", '{"approved_by":"PRIVATE_OWNER"}')
        self.assertEqual(self.get("/api/jobs/" + identifier).json["status"], "interrupted")
        response = self.get("/api/jobs/" + identifier + "/download/approval")
        self.assertEqual(response.status_code, 400)
        self.assertNotIn("PRIVATE_OWNER", response.text)
        self.assertEqual(self.get("/api/jobs/not-an-id").status_code, 400)

    def test_demo_json_download_and_restart_history_are_private(self):
        from vaptkit.dashboard import Jobs
        from vaptkit.dashboard_worker import demo
        identifier = "c" * 32
        root = self.root / "data" / identifier
        create_output(root)
        write_private(root / "job.json", json.dumps({"id": identifier, "profile": "demo", "project": "demonstration",
                                                   "created_at": "2026-10-01T00:00:00Z"}))
        demo(root)
        write_private(root / "outcome.json", '{"status":"completed","message":"Synthetic report."}')
        response = self.get("/api/jobs/" + identifier + "/download/json")
        self.assertEqual(response.status_code, 200)
        self.assertIn("attachment", response.headers["Content-Disposition"])
        self.assertEqual(response.json["status"], "fixture")
        response.close()
        self.assertEqual((root / "assessment/assessment.json").stat().st_mode & 0o777, 0o600)
        reloaded = Jobs(self.root / "data")
        self.assertEqual(reloaded.result(identifier)["status"], "completed")

    def test_worker_crash_or_timeout_is_explicit_and_secrets_are_cleared(self):
        for timed_out in (False, True):
            with self.subTest(timed_out=timed_out):
                identifier = ("d" if timed_out else "e") * 32
                output = self.root / "data" / identifier
                create_output(output)
                spec = {"profile": "roles", "credentials": {"DTAP_QA_PASSWORD": "PRIVATE_SENTINEL"}}
                self.jobs.active = identifier
                with patch("vaptkit.dashboard.subprocess.Popen") as popen, patch(
                    "vaptkit.dashboard.os.killpg"
                ) as kill:
                    process = popen.return_value
                    process.pid = 12345
                    process.returncode = 1
                    if timed_out:
                        process.communicate.side_effect = [subprocess.TimeoutExpired("worker", 1), (None, None)]
                    self.jobs.work(identifier, spec)
                    self.assertNotIn("PRIVATE_SENTINEL", repr(popen.call_args))
                    self.assertIn("PRIVATE_SENTINEL", process.communicate.call_args_list[0].args[0].decode())
                    self.assertEqual(bool(kill.call_count), timed_out)
                self.assertEqual(spec["credentials"], {})
                self.assertIsNone(self.jobs.active)
                outcome = load_json(output / "outcome.json")
                self.assertEqual(outcome["status"], "failed")
                self.assertNotIn("PRIVATE_SENTINEL", json.dumps(outcome))

    def test_worker_does_not_export_qa_credentials_to_environment(self):
        from vaptkit.dashboard_worker import execute
        root = self.root / "worker"
        create_output(root)
        spec = {"profile": "roles", "config": self.config,
                "approval": approval_for(self.config), "credentials": dict(ENV)}
        app = Application()
        def request(*args, **kwargs):
            self.assertNotEqual(os.environ.get("DTAP_QA_PASSWORD"), ENV["DTAP_QA_PASSWORD"])
            return app(*args, **kwargs)
        with patch.dict(os.environ, {}, clear=True), patch("vaptkit.roles.request", side_effect=request), patch(
            "vaptkit.roles.time.sleep"
        ), patch("vaptkit.dashboard_worker.generate"):
            outcome = execute(spec, root)
        self.assertEqual(outcome["status"], "completed")
        self.assertEqual(spec["credentials"], {})
        for value in ENV.values():
            self.assertNotIn(value, (root / "assessment/assessment.json").read_text())

    def test_cloud_credentials_are_copied_only_to_private_temporary_storage(self):
        from vaptkit.dashboard_worker import prepare_gcloud
        source = self.root / "synthetic-cloud-source"
        source.mkdir()
        (source / "credentials.db").write_text("SYNTHETIC_CREDENTIAL_DATABASE")
        (source / "active_config").write_text("default")
        (source / "configurations").mkdir()
        (source / "configurations/config_default").write_text("[core]\naccount = fixture@example.invalid\n")
        (source / "logs").mkdir()
        (source / "logs/private.log").write_text("DO_NOT_COPY")
        destination = self.root / "worker-private"
        destination.mkdir()
        with patch("vaptkit.dashboard_worker.Path", return_value=source), patch.dict(os.environ, {}, clear=True):
            prepare_gcloud(destination)
            copied = Path(os.environ["CLOUDSDK_CONFIG"])
            self.assertEqual(copied, destination / "gcloud")
            self.assertEqual(copied.stat().st_mode & 0o777, 0o700)
            self.assertEqual((copied / "credentials.db").stat().st_mode & 0o777, 0o600)
            self.assertFalse((copied / "logs").exists())
        self.assertEqual((source / "credentials.db").read_text(), "SYNTHETIC_CREDENTIAL_DATABASE")

    def test_template_uses_external_scripts_and_no_remote_assets(self):
        response = self.client.get("/", base_url=self.origin)
        self.assertIn('src="/assets/app.js"', response.text)
        self.assertNotIn("https://", response.text)
        self.assertEqual(self.get("/assets/unknown.js").status_code, 404)
        self.assertEqual(self.post("/api/jobs", ["not", "an", "object"]).status_code, 400)
