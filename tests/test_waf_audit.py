import json
import unittest

from test_waf_lab import audit_events


class WafAuditTests(unittest.TestCase):
    def event(self, key="a" * 32, status=403, rule="941100"):
        return json.dumps({"transaction": {
            "request": {"uri": "/echo?key=" + key + "&q=PRIVATE_SYNTHETIC_VALUE"},
            "response": {"http_code": status},
            "messages": [{"details": {"ruleId": rule, "data": "PRIVATE_MATCH_DATA"}}],
        }})

    def test_only_correlated_status_and_rule_ids_retained(self):
        events = audit_events(self.event())
        self.assertEqual(events, {"a" * 32: {"status": 403, "rules": {"941100"}}})
        self.assertNotIn("PRIVATE", repr(events))

    def test_duplicate_or_invalid_correlation_is_not_accepted(self):
        for text in (self.event() + "\n" + self.event(), self.event(key="invalid"), " " * 2_000_001):
            with self.assertRaises(AssertionError):
                audit_events(text)

    def test_unmatched_health_checks_not_counted(self):
        self.assertEqual(audit_events(json.dumps({
            "transaction": {"request": {"uri": "/ready"}, "response": {"http_code": 200}}
        })), {})
