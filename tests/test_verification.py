import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from test_assessment import ROOT, approved, observation
from vaptkit.assessment import assess, compare, findings_for, verify
from vaptkit.config import load_config
from vaptkit.process import ToolError
from vaptkit.report import validate_result


class VerificationTests(unittest.TestCase):
    def test_reproduced_or_changed_and_one_repeat_per_path(self):
        initial = observation()
        for protected, expected in ((False, "confirmed"), (True, "suspected")):
            with self.subTest(protected=protected):
                repeat = Mock(return_value=observation(protected=protected))
                observations = []
                findings = verify(findings_for(initial), observations, repeat)
                self.assertEqual({item["verification"] for item in findings}, {expected})
                self.assertEqual(len(observations), 1)
                repeat.assert_called_once_with("/")

    def test_failed_verification_never_looks_clean(self):
        config = load_config(ROOT / "projects/pemedes.vapt.yml")
        for status in (302, 401, 403, 404, 429, 503):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as directory, patch(
                "vaptkit.assessment.time.sleep"
            ), patch("vaptkit.assessment.observe", side_effect=[observation(), observation(status=status)]):
                output, code = assess(config, approved(config), Path(directory) / "out")
                result = json.loads(output.read_text())
                validate_result(result)
                self.assertEqual(code, 1)
                self.assertEqual(result["status"], "incomplete")
                self.assertTrue(result["findings"])
                self.assertNotIn("confirmed", {item["verification"] for item in result["findings"]})

    def test_retest_needs_equivalent_check_and_two_successful_results(self):
        old = observation()
        baseline = {"observations": [old], "findings": findings_for(old)}
        result = {"observations": [observation(protected=True)], "findings": []}
        self.assertEqual({row["status"] for row in compare(baseline, result)}, {"not_rechecked"})
        result["verification_observations"] = [observation(protected=True)]
        self.assertEqual({row["status"] for row in compare(baseline, result)}, {"resolved"})
        baseline["findings"].append(dict(baseline["findings"][0], title="Missing route authorization",
                                         category="unauthorized_access"))
        self.assertEqual(compare(baseline, result)[-1]["status"], "not_rechecked")

    def test_missing_graded_key_does_not_resolve_old_finding(self):
        old = observation(protected=True)
        old["checks"]["cookies_secure"] = False
        baseline = {"observations": [old], "findings": findings_for(old)}
        result = {"observations": [observation(protected=True)], "findings": [],
                  "verification_observations": [observation(protected=True)]}
        self.assertEqual(compare(baseline, result)[0]["status"], "not_rechecked")

    def test_retest_does_not_treat_header_request_as_exposure_recheck(self):
        finding = dict(findings_for(observation())[0], title="Environment file publicly downloadable",
                       path="/.env", category="data_exposure")
        baseline = {"observations": [], "findings": [finding],
                    "exposure": [{"path": "/.env", "exposed": True}]}
        result = {"observations": [observation("/.env", protected=True)], "findings": []}
        self.assertEqual(compare(baseline, result)[0]["status"], "not_rechecked")
        result["exposure"] = [{"path": "/.env", "status": 403}]
        self.assertEqual(compare(baseline, result)[0]["status"], "not_rechecked")
        result["exposure"][0]["status"] = 404
        self.assertEqual(compare(baseline, result)[0]["status"], "resolved")

    def test_baseline_target_and_schema_checked_before_traffic(self):
        config = load_config(ROOT / "projects/pemedes.vapt.yml")
        baseline = json.loads((ROOT / "tests/fixtures/assessment.json").read_text())
        for bad in ([], {}, dict(baseline, project=config["project"], target="https://other.invalid")):
            with self.subTest(bad=bad), tempfile.TemporaryDirectory() as directory, patch(
                "vaptkit.assessment.observe"
            ) as request:
                with self.assertRaises(ToolError):
                    assess(config, approved(config), Path(directory) / "out", bad)
                request.assert_not_called()

    def test_retest_resolved_paths_are_repeated_even_without_new_findings(self):
        config = load_config(ROOT / "projects/pemedes.vapt.yml")
        with tempfile.TemporaryDirectory() as directory, patch("vaptkit.assessment.time.sleep"), patch(
            "vaptkit.assessment.observe", return_value=observation()
        ):
            root = Path(directory)
            first, _ = assess(config, approved(config), root / "first")
            baseline = json.loads(first.read_text())
            with patch("vaptkit.assessment.observe", return_value=observation(protected=True)) as repeat:
                second, code = assess(config, approved(config), root / "second", baseline)
            result = json.loads(second.read_text())
            validate_result(result)
            self.assertEqual(code, 0)
            self.assertEqual(repeat.call_count, 2)
            self.assertEqual({row["status"] for row in result["retest"]}, {"resolved"})

    def test_exposure_opt_in_and_stops_preserve_partial_evidence(self):
        config = load_config(ROOT / "projects/pemedes.vapt.yml")
        approval = approved(config)
        approval["exposure_checks"] = True
        with tempfile.TemporaryDirectory() as directory, patch("vaptkit.assessment.time.sleep"), patch(
            "vaptkit.assessment.observe", return_value=observation(protected=True)
        ), patch("vaptkit.assessment.request", side_effect=[
            (404, {}, b""), (200, {"content-type": ["text/plain"]}, b""),
            (206, {"content-type": ["text/plain"]}, b"SYNTHETIC_KEY=value"),
            (429, {}, b""),
        ]) as request:
            output, code = assess(config, approval, Path(directory) / "out")
            result = json.loads(output.read_text())
            validate_result(result)
            self.assertEqual(code, 1)
            self.assertEqual(request.call_count, 4)
            self.assertEqual(result["findings"][0]["path"], "/.env")
            self.assertEqual(result["errors"][0]["kind"], "http")
            self.assertEqual(result["requests"][-1]["status"], 429)
            self.assertNotIn("SYNTHETIC_KEY", output.read_text())

    def test_public_exposure_rejects_authenticated_config(self):
        config = load_config(ROOT / "projects/pemedes-iap.vapt.yml")
        approval = approved(config)
        approval["exposure_checks"] = True
        with tempfile.TemporaryDirectory() as directory, patch("vaptkit.assessment.observe") as request:
            with self.assertRaises(ToolError):
                assess(config, approval, Path(directory) / "out")
            request.assert_not_called()
