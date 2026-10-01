import contextlib
import copy
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from vaptkit.armor import cloud_json, collect, review, validate_review, waf_family
from vaptkit.cli import main
from vaptkit.process import ToolError
from vaptkit.report import merge_cloud_review, render, validate_result

ROOT = Path(__file__).resolve().parents[1]
PROJECT, SERVICE, REGION = "fixture-project", "fixture-service", "us-central1"
PREFIX = f"https://www.googleapis.com/compute/v1/projects/{PROJECT}"
NEG = f"{PREFIX}/regions/{REGION}/networkEndpointGroups/fixture-neg"
POLICY = f"{PREFIX}/global/securityPolicies/fixture-policy"
STARTED = "2026-10-01T00:00:00Z"


def inventory():
    run = {"metadata": {"name": SERVICE, "annotations": {
        "run.googleapis.com/ingress": "internal-and-cloud-load-balancing",
        "run.googleapis.com/default-url-disabled": "true",
    }}}
    negs = [{"name": "fixture-neg", "selfLink": NEG, "networkEndpointType": "SERVERLESS",
             "cloudRun": {"service": SERVICE}}]
    backends = [{"name": "fixture-backend", "backends": [{"group": NEG}], "securityPolicy": POLICY,
                 "logConfig": {"enable": True, "sampleRate": 1}}]
    policies = [{"name": "fixture-policy", "selfLink": POLICY, "type": "CLOUD_ARMOR", "rules": [
        {"priority": 100, "action": "deny(403)", "preview": False,
         "match": {"expr": {"expression": "evaluatePreconfiguredWaf('xss-v33-stable', {'sensitivity': 1})"}}},
        {"priority": 200, "action": "deny(403)", "preview": False,
         "match": {"expr": {"expression": "evaluatePreconfiguredWaf('sqli-v33-stable')"}}},
        {"priority": 2147483647, "action": "allow",
         "match": {"versionedExpr": "SRC_IPS_V1", "config": {"srcIpRanges": ["*"]}}},
    ]}]
    return run, negs, backends, policies


class ArmorTests(unittest.TestCase):
    def setUp(self):
        self.base = json.loads((ROOT / "tests/fixtures/assessment.json").read_text())
        self.config = {"project": self.base["project"], "target": {"url": self.base["target"]}}

    def review(self, data=None):
        return review(self.config, PROJECT, SERVICE, REGION, *(data or inventory()), started=STARTED)

    def test_configured_rules_are_references_not_exploit_or_protection_proof(self):
        result = self.review()
        validate_review(result)
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["backends"][0]["xss_enforced_references"], 1)
        self.assertEqual(result["backends"][0]["sqli_enforced_references"], 1)
        self.assertIn("not proof of protection", result["note"])

    def test_preview_shadowing_and_logging_observations(self):
        data = inventory()
        rules = data[3][0]["rules"]
        rules[0]["preview"] = True
        rules[-1]["priority"] = 50
        data[2][0]["logConfig"]["enable"] = False
        result = self.review(data)
        self.assertEqual(len(result["findings"]), 3)
        self.assertEqual(result["backends"][0]["shadowed_waf_rules"], 1)
        self.assertEqual({item["verification"] for item in result["findings"]}, {"observation"})
        self.assertEqual({item["category"] for item in result["findings"]}, {"configuration"})
        data[2][0]["logConfig"] = {"enable": True, "sampleRate": 0}
        self.assertEqual(len(self.review(data)["findings"]), 3)

    def test_missing_policy_association_and_unknowns_are_coverage_gaps(self):
        for change in (
            lambda data: data[1].clear(),
            lambda data: data[1][0]["cloudRun"].update(service="another-service"),
            lambda data: data[1][0]["cloudRun"].update(urlMask="<service>.example.invalid"),
            lambda data: data[2][0].pop("securityPolicy"),
            lambda data: data[3].clear(),
            lambda data: data[0]["metadata"]["annotations"].update({"run.googleapis.com/ingress": "all",
                                                                  "run.googleapis.com/default-url-disabled": "false"}),
            lambda data: data[2][0].update(edgeSecurityPolicy=POLICY),
        ):
            with self.subTest(change=change):
                data = inventory()
                change(data)
                result = self.review(data)
                self.assertEqual(result["status"], "incomplete")
                self.assertTrue(result["gaps"])
                self.assertEqual(result["findings"], [])

    def test_only_standalone_waf_calls_are_recognized(self):
        for expression in (
            "false && evaluatePreconfiguredWaf('xss-v33-stable')",
            "// evaluatePreconfiguredWaf('xss-v33-stable')",
            "\"evaluatePreconfiguredWaf('xss-v33-stable')\"",
            "evaluatePreconfiguredWaf('xss-v33-stable') || true",
            "evaluatePreconfiguredWaf('xss-v33-stable', dangerous())",
            "object.evaluatePreconfiguredWaf('xss-v33-stable')",
        ):
            with self.subTest(expression=expression):
                self.assertIsNone(waf_family(expression))
        self.assertEqual(waf_family("evaluatePreconfiguredExpr('xss-v33-stable')"), "xss")
        self.assertEqual(waf_family("evaluatePreconfiguredWaf('sqli-v422-stable', {'sensitivity': 0, 'opt_in_rule_ids': ['fixture']})"), "sqli")

    def test_raw_expressions_ips_and_annotations_never_persist(self):
        data = inventory()
        data[0]["metadata"]["annotations"]["private"] = "PRIVATE_ANNOTATION"
        data[3][0]["rules"][0]["match"]["expr"]["expression"] = "request.headers['PRIVATE_HEADER'] == 'PRIVATE_VALUE'"
        data[3][0]["rules"][-1]["match"]["config"]["srcIpRanges"] = ["192.0.2.123/32"]
        result = self.review(data)
        text = json.dumps(result) + render(merge_cloud_review(self.base, result))
        for value in ("PRIVATE_ANNOTATION", "PRIVATE_HEADER", "PRIVATE_VALUE", "192.0.2.123"):
            self.assertNotIn(value, text)
        self.assertEqual(result["backends"][0]["unparsed_expressions"], 1)

    def test_invalid_metadata_fails_instead_of_generating_clean_review(self):
        for change in (
            lambda data: data[0]["metadata"].update(name="different-service"),
            lambda data: data[3][0].update(rules=None),
            lambda data: data[3][0]["rules"][1].update(priority=100),
            lambda data: data[3][0]["rules"][0].update(priority=True),
            lambda data: data[2][0].update(logConfig={"sampleRate": 2}),
        ):
            data = inventory()
            change(data)
            with self.assertRaises(ToolError):
                self.review(data)

    def test_collection_is_bounded_read_only_and_explicitly_scoped(self):
        with patch("vaptkit.armor.cloud_json", side_effect=inventory()) as fetch:
            self.assertEqual(collect(self.config, PROJECT, SERVICE, REGION)["status"], "completed")
        self.assertEqual(fetch.call_count, 4)
        for call in fetch.call_args_list:
            args = call.args[0]
            self.assertIn("--project=" + PROJECT, args)
            self.assertTrue("list" in args or "describe" in args)
            self.assertFalse(any(word in args for word in ("update", "create", "delete", "deploy")))
        with patch("vaptkit.armor.cloud_json") as fetch, self.assertRaises(ToolError):
            collect(self.config, "--project=outside", SERVICE, REGION)
        fetch.assert_not_called()

    def test_collection_failures_are_sanitized(self):
        for response in (
            SimpleNamespace(returncode=1, stdout=b"PRIVATE_TOKEN", stderr=b"PRIVATE_TOKEN"),
            SimpleNamespace(returncode=0, stdout=b"PRIVATE_TOKEN"),
            SimpleNamespace(returncode=0, stdout=b"x" * 4_000_001),
            SimpleNamespace(returncode=0, stdout=json.dumps([{}] * 101).encode()),
        ):
            with patch("vaptkit.armor.subprocess.run", return_value=response), self.assertRaises(ToolError) as error:
                cloud_json(["fixture"], inventory=True)
            self.assertNotIn("PRIVATE_TOKEN", str(error.exception))
        with patch("vaptkit.armor.subprocess.run", side_effect=subprocess.TimeoutExpired("gcloud", 45)):
            with self.assertRaises(ToolError):
                cloud_json(["fixture"])

    def test_cli_requires_permission_before_cloud_access(self):
        with tempfile.TemporaryDirectory() as directory, patch("vaptkit.armor.collect") as fetch:
            with contextlib.redirect_stderr(io.StringIO()):
                code = main(["review-armor", str(ROOT / "templates/project.example.yml"),
                             "--gcp-project", PROJECT, "--service", SERVICE, "--region", REGION,
                             "--output", str(Path(directory) / "out.json")])
            self.assertEqual(code, 2)
            fetch.assert_not_called()

    def test_cli_writes_private_review_and_preserves_incomplete_status(self):
        cloud = self.review()
        cloud.update(status="incomplete", gaps=["Synthetic association gap."])
        with tempfile.TemporaryDirectory() as directory, patch(
            "vaptkit.armor.collect", return_value=cloud
        ) as fetch, contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            output = Path(directory) / "review.json"
            args = ["review-armor", str(ROOT / "templates/project.example.yml"),
                    "--gcp-project", PROJECT, "--service", SERVICE, "--region", REGION,
                    "--acknowledge-scope", "--output", str(output)]
            self.assertEqual(main(args), 1)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads(output.read_text())["status"], "incomplete")
            self.assertEqual(main(args), 2)
            fetch.assert_called_once()

    def test_report_binding_and_no_application_coverage_upgrade(self):
        cloud = self.review()
        merged = merge_cloud_review(self.base, cloud)
        validate_result(merged)
        for category in ("data_exposure", "unauthorized_access"):
            self.assertEqual(merged["coverage"][category], self.base["coverage"][category])
        self.assertIn("separate read-only Cloud Armor", merged["coverage"]["note"])
        self.assertIn("Cloud Armor Configuration Review", render(merged))
        self.assertIn("not verified blocking", render(merged))
        bad = copy.deepcopy(cloud)
        bad["target"] = "https://another.example.invalid"
        with self.assertRaises(ToolError):
            merge_cloud_review(self.base, bad)
        bad = copy.deepcopy(cloud)
        bad["raw_headers"] = "PRIVATE_TOKEN"
        with self.assertRaises(ToolError):
            merge_cloud_review(self.base, bad)
        with self.assertRaises(ToolError):
            merge_cloud_review(merged, cloud)
