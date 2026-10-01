import unittest

from vaptkit.waf import WafEvidence, evaluate_waf


class WafTests(unittest.TestCase):
    def test_block_requires_correlated_rule_and_origin_evidence(self):
        control = WafEvidence(200, True, True)
        blocked = WafEvidence(403, False, False, True, True, True)
        self.assertEqual(evaluate_waf(control, [blocked, blocked]), "blocked")
        for evidence in (
            WafEvidence(403, False, False),
            WafEvidence(403, False, False, True, False, True),
            WafEvidence(403, False, False, True, True, False),
            WafEvidence(403, False, True, True, True, True),
        ):
            self.assertEqual(evaluate_waf(control, [evidence, evidence]), "inconclusive")

    def test_origin_denial_is_not_waf_block(self):
        denied = WafEvidence(403, True, True)
        self.assertEqual(evaluate_waf(denied, [denied, denied]), "origin_denied")

    def test_preview_match_with_origin_delivery_is_passed_not_blocked(self):
        control = WafEvidence(200, True, True)
        detected = WafEvidence(200, True, True, True, True, True)
        self.assertEqual(evaluate_waf(control, [detected, detected]), "passed")

    def test_missing_control_repetition_or_inconsistent_results(self):
        passed = WafEvidence(200, True, True)
        blocked = WafEvidence(403, False, False, True, True, True)
        self.assertEqual(evaluate_waf(WafEvidence(200, False, False), [blocked, blocked]), "inconclusive")
        self.assertEqual(evaluate_waf(passed, [blocked]), "inconclusive")
        self.assertEqual(evaluate_waf(passed, [blocked, passed]), "inconclusive")
