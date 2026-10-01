import json
import unittest
from dataclasses import asdict, replace

from vaptkit.authorization import (
    ObjectExpectation, TransitionEvidence, evaluate_read, evaluate_transition, observe_object,
)


class AuthorizationEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.expected = ObjectExpectation("doc-a", "alice", "SYNTHETIC_PRIVATE")
        self.payload = {
            "data": {"id": "doc-a", "owner": "alice", "private_note": "SYNTHETIC_PRIVATE",
                     "phase": "draft", "revision": 0, "last_actor": "bob", "last_action": "edit"},
        }

    def observe(self, payload=None, status=200):
        return observe_object(status, {"content-type": ["application/json"]},
                              json.dumps(self.payload if payload is None else payload).encode(),
                              self.expected, actor="bob", action="edit")

    def test_matching_evidence_retains_no_private_fields(self):
        item = self.observe()
        self.assertTrue(item.object_matches)
        self.assertTrue(item.actor_matches)
        self.assertNotIn("SYNTHETIC_PRIVATE", json.dumps(asdict(item)))
        for field in ("id", "owner", "private_note"):
            bad = {"data": dict(self.payload["data"], **{field: "different"})}
            self.assertFalse(self.observe(bad).object_matches)

    def test_bad_bodies_never_establish_denial(self):
        control = self.observe()
        for body in (b"<html>Denied</html>", b"{", b"x" * 65537,
                     b'{"data":null,"data":null}', b'{"data":NaN}'):
            item = observe_object(403, {"content-type": ["application/json"]}, body, self.expected)
            self.assertEqual(evaluate_read(control, [item, item], allowed=False), "inconclusive")

    def test_read_requires_control_repetition_and_exact_content(self):
        good = self.observe()
        denied = self.observe({"error": "Denied"}, status=403)
        self.assertEqual(evaluate_read(good, [good, good], allowed=False), "violation")
        self.assertEqual(evaluate_read(good, [good, good], allowed=True), "allowed")
        self.assertEqual(evaluate_read(good, [denied, denied], allowed=False), "denied")
        for control, attempts in ((denied, [good, good]), (good, [good]), (good, [good, denied])):
            self.assertEqual(evaluate_read(control, attempts, allowed=False), "inconclusive")

    def test_transition_needs_attributed_single_version_change(self):
        before = self.observe()
        after = replace(before, revision=1)
        control = TransitionEvidence(before, 200, after)
        for bad_after in (
            replace(after, revision=0), replace(after, revision=2), replace(after, actor_matches=False),
            replace(after, action_matches=False), replace(after, phase=None),
            replace(after, object_matches=False), replace(after, status=503),
        ):
            candidate = TransitionEvidence(before, 200, bad_after)
            self.assertEqual(evaluate_transition(control, [candidate, candidate], control_from="draft",
                                                from_phase="draft", to_phase="draft", allowed=False), "inconclusive")
        denied_but_changed = TransitionEvidence(before, 403, after)
        self.assertEqual(evaluate_transition(control, [denied_but_changed] * 2, control_from="draft",
                                            from_phase="draft", to_phase="draft", allowed=False), "violation")
        self.assertEqual(evaluate_transition(control, [control], control_from="draft",
                                            from_phase="draft", to_phase="draft", allowed=False), "inconclusive")
        bad_control = TransitionEvidence(before, 200, before)
        self.assertEqual(evaluate_transition(bad_control, [control] * 2, control_from="draft",
                                            from_phase="draft", to_phase="draft", allowed=False), "inconclusive")

    def test_revision_and_phase_validation(self):
        for revision in (-1, True, "1", 1.5, None):
            self.payload["data"]["revision"] = revision
            self.assertIsNone(self.observe().revision)
        self.payload["data"]["phase"] = "unknown"
        self.assertIsNone(self.observe().phase)
