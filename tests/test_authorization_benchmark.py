"""Loopback-only behavioral benchmark against a separately maintained outcome manifest."""
import json
import shutil
import socket
import unittest
from contextlib import ExitStack
from dataclasses import asdict
from http.cookies import SimpleCookie
from pathlib import Path
from unittest.mock import patch

import test_https_integration
from fixtures.authorization_app import Application, Handler, USERS
from vaptkit.assessment import request
from vaptkit.authorization import (
    ObjectExpectation, TransitionEvidence, evaluate_read, evaluate_transition, observe_object,
)

HOST = "staging.example.invalid"
CASES = json.loads((Path(__file__).parent / "fixtures/authorization_cases.json").read_text())["cases"]
CONTROL = {
    "edit": ("alice", "draft", "draft"),
    "submit": ("alice", "draft", "submitted"),
    "review": ("charlie", "submitted", "reviewed"),
    "approve": ("dana", "reviewed", "approved"),
}


@unittest.skipUnless(shutil.which("openssl"), "openssl is required for the loopback HTTPS authorization benchmark")
class AuthorizationBenchmark(unittest.TestCase):
    handler = Handler
    setUpClass = classmethod(test_https_integration.HTTPSIntegrationTests.setUpClass.__func__)

    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        real_connect = socket.create_connection

        def public_addresses(host):
            self.assertEqual(host, HOST, "Benchmark must not accept any application target")
            return ["8.8.8.8"]

        def connect(address, timeout):
            self.assertEqual(address, ("8.8.8.8", 443))
            return real_connect(self.server.server_address, timeout=timeout)

        for mock in (
            patch("vaptkit.assessment.public_addresses", side_effect=public_addresses),
            patch("vaptkit.assessment.socket.create_connection", side_effect=connect),
            patch("vaptkit.assessment.ssl.create_default_context", return_value=self.client_tls),
        ):
            self.stack.enter_context(mock)

    def call(self, method, path, user=None, body=None):
        headers = {"Accept": "application/json"}
        if user and user != "anonymous":
            headers["Cookie"] = self.sessions[user]
        if body is not None:
            headers["Content-Type"] = "application/json"
        return request(HOST, method, path, headers=headers,
                       body=json.dumps(body).encode() if body is not None else None, body_limit=65537)

    def login(self):
        self.sessions = {}
        for user in USERS:
            status, headers, body = self.call("POST", "/login", body={"user": user, "password": "synthetic-only"})
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(body)["user"], user)
            cookies = SimpleCookie()
            cookies.load(headers["set-cookie"][0])
            self.sessions[user] = "fixture-session=" + cookies["fixture-session"].value
        self.assertEqual(len(set(self.sessions.values())), len(USERS))

    def logout(self):
        for user in USERS:
            status, _, body = self.call("POST", "/logout", user)
            self.assertEqual(status, 200)
            self.assertTrue(json.loads(body)["success"])
        self.assertEqual(self.server.application.sessions, {})
        self.assertEqual(self.server.application.revocations, len(USERS))
        # Check revoked cookies, not just successful logout acknowledgements.
        status, _, _ = self.call("GET", "/documents/owned", "alice")
        self.assertEqual(status, 401)

    def evidence(self, identifier, owner, reader, *, actor=None, action=None):
        return observe_object(
            *self.call("GET", f"/documents/{identifier}", reader),
            ObjectExpectation(identifier, owner, f"SYNTHETIC_PRIVATE_{identifier}"),
            actor=actor, action=action,
        )

    def transition(self, identifier, owner, actor, action):
        before = self.evidence(identifier, owner, "charlie")
        status, _, _ = self.call("POST", f"/documents/{identifier}/{action}", actor, {})
        after = self.evidence(identifier, owner, "charlie", actor=actor, action=action)
        return TransitionEvidence(before, status, after)

    def exercise(self, case):
        app = Application(case["mode"])
        self.server.application = app
        self.login()
        try:
            app.seed("owned", "alice")
            app.seed("other", "bob")
            if case["kind"] == "read":
                app.seed("target", case["owner"], shared=case.get("shared", []))
                control = self.evidence("target", case["owner"], case["owner"])
                attempts = [self.evidence("target", case["owner"], case["actor"]) for _ in range(2)]
                result = evaluate_read(control, attempts, allowed=case["allowed"])
            else:
                action = case["action"]
                control_actor, control_from, target_phase = CONTROL[action]
                app.seed("control", "alice", control_from)
                control = self.transition("control", "alice", control_actor, action)
                attempts = []
                for index in range(2):
                    identifier = f"trial-{index}"
                    app.seed(identifier, case["owner"], case["phase"])
                    attempts.append(self.transition(identifier, case["owner"], case["actor"], action))
                result = evaluate_transition(
                    control, attempts, control_from=control_from, from_phase=case["phase"],
                    to_phase=target_phase, allowed=case["allowed"],
                )
            evidence = {"control": asdict(control), "attempts": [asdict(item) for item in attempts]}
            serialized = json.dumps(evidence)
            self.assertNotIn("SYNTHETIC_PRIVATE", serialized)
            self.assertNotIn("synthetic-only", serialized)
            for cookie in self.sessions.values():
                self.assertNotIn(cookie, serialized)
            return result
        finally:
            # Mutants intentionally defeat access control; use the safe mode for revocation checks.
            app.mode = "safe"
            self.logout()

    def test_reference_backed_manifest(self):
        counts = {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "inconclusive": 0, "misclassified": 0}
        self.assertEqual(len({case["id"] for case in CASES}), len(CASES))
        results = []
        for case in CASES:
            with self.subTest(case=case["id"]):
                actual = self.exercise(case)
                expected = case["expected"]
                results.append({"case": case["id"], "expected": expected, "actual": actual})
                if actual != expected:
                    counts["misclassified"] += 1
                if expected == "inconclusive":
                    if actual == "inconclusive":
                        counts["inconclusive"] += 1
                    elif actual == "violation":
                        counts["fp"] += 1
                elif expected == "violation":
                    counts["tp" if actual == "violation" else "fn"] += 1
                elif actual == "violation":
                    counts["fp"] += 1
                elif actual == expected:
                    counts["tn"] += 1
                self.assertEqual(actual, expected)
        print("\nLocal ownership/workflow benchmark: " + json.dumps(counts, sort_keys=True))
        self.assertEqual(counts["fp"], 0, results)
        self.assertEqual(counts["fn"], 0, results)
        self.assertEqual(counts["misclassified"], 0, results)
        self.assertGreaterEqual(counts["tp"], 10)
        self.assertGreaterEqual(counts["tn"], 10)
        self.assertGreaterEqual(counts["inconclusive"], 8)

    def test_valid_workflow_and_revoked_sessions(self):
        app = Application()
        self.server.application = app
        self.login()
        try:
            app.seed("owned", "alice")
            for actor, action, phase in (("alice", "submit", "submitted"),
                                         ("charlie", "review", "reviewed"),
                                         ("dana", "approve", "approved")):
                evidence = self.transition("owned", "alice", actor, action)
                self.assertEqual(evidence.action_status, 200)
                self.assertEqual(evidence.after.phase, phase)
                self.assertEqual(evidence.after.revision, evidence.before.revision + 1)
                self.assertTrue(evidence.after.actor_matches)
            replay = self.transition("owned", "alice", "dana", "approve")
            self.assertEqual(replay.action_status, 409)
            self.assertEqual(replay.before.revision, replay.after.revision)
        finally:
            self.logout()

    def test_no_nonfixture_host_accepted(self):
        with self.assertRaises(AssertionError):
            request("test.dtap.dict.gov.ph", "GET", "/")


if __name__ == "__main__":
    unittest.main()
