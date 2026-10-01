"""Local WAF evidence classification. Not a Cloud Armor or live exploitation adapter."""
from dataclasses import dataclass


@dataclass(frozen=True)
class WafEvidence:
    status: int
    marker_matches: bool
    origin_seen: bool
    audit_matched: bool = False
    family_matched: bool = False
    blocking_rule_matched: bool = False


def evaluate_waf(control: WafEvidence, attempts: list[WafEvidence]) -> str:
    if not control.marker_matches or not control.origin_seen or len(attempts) != 2:
        return "inconclusive"
    if control.status == 403 and all(
        item.status == 403 and item.marker_matches and item.origin_seen for item in attempts
    ):
        return "origin_denied"
    if control.status != 200:
        return "inconclusive"
    if all(item.status == 403 and not item.marker_matches and not item.origin_seen
           and item.audit_matched and item.family_matched and item.blocking_rule_matched for item in attempts):
        return "blocked"
    if all(item.status == 200 and item.marker_matches and item.origin_seen for item in attempts):
        return "passed"
    return "inconclusive"
