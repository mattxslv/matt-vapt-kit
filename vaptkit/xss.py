"""Derived browser evidence for the local XSS lab, not a live scanning adapter."""
from dataclasses import dataclass


@dataclass(frozen=True)
class XssEvidence:
    status: int
    html_assessed: bool
    execution_observed: bool
    reflection_observed: bool = False
    csp_blocked: bool = False
    browser_failed: bool = False
    same_document: bool = True


def evaluate_xss(control_executed: bool, attempts: list[XssEvidence]) -> str:
    if not control_executed or len(attempts) != 2:
        return "inconclusive"
    if any(item.browser_failed or not item.html_assessed or not item.same_document for item in attempts):
        return "inconclusive"
    if all(item.execution_observed for item in attempts):
        return "confirmed"
    if any(item.execution_observed or item.csp_blocked for item in attempts):
        return "inconclusive"
    if all(200 <= item.status < 300 for item in attempts):
        return "not_reproduced"
    return "inconclusive"
