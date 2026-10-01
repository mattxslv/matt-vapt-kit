"""Opt-in real ModSecurity/CRS benchmark with no egress or published ports."""
import json
import os
import re
import subprocess
import time
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from vaptkit.waf import WafEvidence, evaluate_waf

FIXTURES = Path(__file__).parent / "fixtures"
IMAGES = json.loads((FIXTURES / "waf-images.json").read_text())
MANIFEST = json.loads((FIXTURES / "waf_cases.json").read_text())


def docker(*args, input=None, timeout=30):
    try:
        result = subprocess.run(["docker", *args], input=input, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        raise AssertionError("Local WAF Docker operation failed or timed out; raw output withheld.") from None
    if result.returncode:
        raise AssertionError("Local WAF Docker operation failed; check Docker and the documented image prerequisites.")
    return result.stdout


def audit_events(text):
    if len(text) > 2_000_000:
        raise AssertionError("Local audit output exceeded its limit.")
    events = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        transaction = json.loads(line)["transaction"]
        key = parse_qs(urlsplit(transaction["request"]["uri"]).query).get("key", [None])[0]
        if key is None:
            continue
        if not re.fullmatch(r"[a-f0-9]{32}", key) or key in events:
            raise AssertionError("Ambiguous local audit correlation.")
        rules = {
            str(message["details"]["ruleId"])
            for message in transaction.get("messages", [])
        }
        events[key] = {"status": transaction["response"]["http_code"], "rules": rules}
    return events


@unittest.skipUnless(os.environ.get("MVK_RUN_WAF_LAB") == "1", "opt-in isolated ModSecurity/CRS lab")
class WafContainerLab(unittest.TestCase):
    def container(self, *args):
        identifier = docker("run", "--detach", "--rm", "--pull=never", "--log-driver=none",
                            "--cap-drop=ALL", "--security-opt=no-new-privileges",
                            "--memory=512m", "--cpus=1", "--pids-limit=128", *args).strip()
        self.assertRegex(identifier, r"^[a-f0-9]{64}$")
        self.addCleanup(self.remove_container, identifier)
        return identifier

    def remove_container(self, identifier):
        # Stop only this test's container; --rm removes its writable layer and audit file.
        docker("stop", "--time=5", identifier, timeout=20)
        result = subprocess.run(["docker", "container", "ls", "--all", "--quiet", "--filter", "id=" + identifier],
                                capture_output=True, text=True, check=True, timeout=10)
        self.assertEqual(result.stdout.strip(), "", "Lab container cleanup was not confirmed")

    def ready(self, origin, port):
        script = (
            "import http.client; c=http.client.HTTPConnection('127.0.0.1',"
            f"{port},timeout=2); c.request('GET','/ready',headers={{'Host':'fixture.local'}}); "
            "r=c.getresponse(); raise SystemExit(0 if r.status == 200 else 1)"
        )
        for _ in range(30):
            result = subprocess.run(["docker", "exec", origin, "python", "-c", script],
                                    capture_output=True, timeout=5)
            if result.returncode == 0:
                return
            time.sleep(1)
        self.fail("Local origin/WAF did not become ready; no benchmark success claimed.")

    def test_real_enforcement_and_detection_only(self):
        self.assertRegex(IMAGES["waf"], r"^owasp/modsecurity-crs@sha256:[a-f0-9]{64}$")
        for image in IMAGES.values():
            docker("image", "inspect", image)
        origin_image = docker("image", "inspect", IMAGES["origin"], "--format={{.Id}}").strip()
        self.assertRegex(origin_image, r"^sha256:[a-f0-9]{64}$")
        cases = MANIFEST["cases"]
        self.assertEqual(MANIFEST["version"], 1)
        self.assertEqual(len(cases), 9)
        self.assertEqual(len({case["id"] for case in cases}), 9)
        for mode in ("On", "DetectionOnly"):
            with self.subTest(mode=mode):
                # Fresh namespace and origin for each mode, with cleanup even on failure.
                origin = self.container(
                    "--network=none", "--read-only",
                    "--mount", f"type=bind,src={FIXTURES / 'waf_origin.py'},dst=/fixture.py,readonly",
                    "--entrypoint=python", origin_image, "/fixture.py",
                )
                self.ready(origin, 8081)
                waf = self.container(
                    "--network=container:" + origin,
                    "-e", "BACKEND=http://127.0.0.1:8081", "-e", "SERVER_NAME=fixture.local",
                    "-e", "MODSEC_RULE_ENGINE=" + mode,
                    "-e", "BLOCKING_PARANOIA=1", "-e", "ANOMALY_INBOUND=5",
                    "-e", "MODSEC_AUDIT_ENGINE=On", "-e", "MODSEC_AUDIT_LOG=/tmp/waf-audit.json",
                    "-e", "MODSEC_AUDIT_LOG_FORMAT=JSON", "-e", "MODSEC_AUDIT_LOG_PARTS=ABFHZ",
                    "-e", "ACCESSLOG=/dev/null", "-e", "ERRORLOG=/dev/null",
                    "-e", "MODSEC_RESP_BODY_ACCESS=Off", "-e", "MODSEC_STATUS_ENGINE=Off",
                    IMAGES["waf"],
                )
                self.ready(origin, 8080)
                for container, expected in ((origin, "none"), (waf, "container:" + origin)):
                    state = json.loads(docker("inspect", container))[0]
                    self.assertEqual(state["HostConfig"]["NetworkMode"], expected)
                    self.assertFalse(state["HostConfig"].get("PortBindings"))
                facts = json.loads(docker(
                    "exec", "-i", origin, "python", "-c", (FIXTURES / "waf_client.py").read_text(),
                    input=json.dumps(cases), timeout=90,
                ))
                expected_keys = {attempt["key"] for row in facts for attempt in row["attempts"]}
                self.assertEqual(len(expected_keys), len(cases) * 2)
                events = {}
                for _ in range(10):
                    events = audit_events(docker("exec", waf, "cat", "/tmp/waf-audit.json"))
                    if expected_keys <= events.keys():
                        break
                    time.sleep(0.2)
                self.assertTrue(expected_keys <= events.keys(), "Audit correlation incomplete")
                self.assertEqual([row["id"] for row in facts], [case["id"] for case in cases])
                counts = {"blocked": 0, "passed": 0, "origin_denied": 0, "inconclusive": 0}
                false_positives = misses = 0
                for case, row in zip(cases, facts):
                    control = WafEvidence(**{key: value for key, value in row["control"].items() if key != "key"})
                    attempts = []
                    for fact in row["attempts"]:
                        event = events[fact["key"]]
                        self.assertEqual(event["status"], fact["status"], "Audit response status mismatch")
                        family_match = any(
                            rule.startswith(case["family"]) if case["family"] else bool(re.fullmatch(r"9[0-9]{5}", rule))
                            for rule in event["rules"]
                        )
                        attempts.append(WafEvidence(
                            status=fact["status"], marker_matches=fact["marker_matches"],
                            origin_seen=fact["origin_seen"], audit_matched=event["status"] == fact["status"],
                            family_matched=family_match, blocking_rule_matched="949110" in event["rules"],
                        ))
                        if case["family"]:
                            self.assertTrue(family_match, f"{case['id']}: expected signature family not recorded")
                    outcome = evaluate_waf(control, attempts)
                    expected = "passed" if mode == "DetectionOnly" and case["family"] else case["expected"]
                    counts[outcome] += 1
                    false_positives += int(not case["family"] and outcome == "blocked")
                    misses += int(mode == "On" and bool(case["family"]) and outcome != "blocked")
                    self.assertEqual(outcome, expected, f"{mode}: {case['id']}")
                self.assertEqual(false_positives, 0)
                self.assertEqual(misses, 0)
                self.assertEqual(counts, {"blocked": 4 if mode == "On" else 0,
                                          "passed": 4 if mode == "On" else 8,
                                          "origin_denied": 1, "inconclusive": 0})
                print(f"\nLocal ModSecurity/CRS {mode}: " + json.dumps(counts, sort_keys=True))
