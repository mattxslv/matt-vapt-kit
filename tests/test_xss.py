import unittest

from vaptkit.xss import XssEvidence, evaluate_xss


class XssEvidenceTests(unittest.TestCase):
    def test_reflection_is_not_execution(self):
        reflected = XssEvidence(200, True, False, reflection_observed=True)
        self.assertEqual(evaluate_xss(True, [reflected, reflected]), "not_reproduced")

    def test_repeated_browser_execution_requires_control(self):
        executed = XssEvidence(200, True, True, reflection_observed=True)
        self.assertEqual(evaluate_xss(True, [executed, executed]), "confirmed")
        self.assertEqual(evaluate_xss(False, [executed, executed]), "inconclusive")
        self.assertEqual(evaluate_xss(True, [executed]), "inconclusive")
        self.assertEqual(evaluate_xss(True, [executed, XssEvidence(200, True, False)]), "inconclusive")

    def test_csp_failure_redirect_and_denial_are_not_passing_controls(self):
        for evidence in (
            XssEvidence(200, True, False, csp_blocked=True),
            XssEvidence(200, True, False, browser_failed=True),
            XssEvidence(200, True, False, same_document=False),
            XssEvidence(401, True, False),
            XssEvidence(200, False, False),
        ):
            self.assertEqual(evaluate_xss(True, [evidence, evidence]), "inconclusive")

    def test_error_status_does_not_excuse_actual_execution(self):
        executed = XssEvidence(403, True, True)
        self.assertEqual(evaluate_xss(True, [executed, executed]), "confirmed")
