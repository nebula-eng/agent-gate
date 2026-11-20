"""Policy compilation and the approval authority."""

from __future__ import annotations

import unittest

from agent_gate.labels import Confidentiality, Integrity, Label
from agent_gate.lattice import declassify
from agent_gate.policy import (
    DEFAULT_POLICY_JSON,
    ApprovalAuthority,
    Policy,
)

CLEAN = Label()
DIRTY = Label(Integrity.UNTRUSTED, Confidentiality.PUBLIC)
SECRET = Label(Integrity.TRUSTED, Confidentiality.SECRET)
BOTH = Label(Integrity.UNTRUSTED, Confidentiality.SECRET)
SINK = "api.internal.example"


class TestStaticRules(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = Policy.default()

    def test_clean_egress_allowed(self) -> None:
        decision = self.policy.check(CLEAN, "NET", SINK)
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.rule_id, "R-NET-CLEAN")

    def test_untrusted_egress_denied(self) -> None:
        decision = self.policy.check(DIRTY, "NET", SINK)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.rule_id, "R-NET-UNTRUSTED")

    def test_secret_egress_denied(self) -> None:
        decision = self.policy.check(SECRET, "NET", SINK)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.rule_id, "R-NET-SECRET")

    def test_rule_order_prefers_integrity(self) -> None:
        decision = self.policy.check(BOTH, "NET", SINK)
        self.assertEqual(decision.rule_id, "R-NET-UNTRUSTED")

    def test_reads_are_not_sinks(self) -> None:
        self.assertTrue(self.policy.check(DIRTY, "NET_IN", SINK).allowed)
        self.assertTrue(self.policy.check(SECRET, "FS_READ", "notes").allowed)

    def test_declassify_denied_by_static_policy(self) -> None:
        decision = self.policy.check(SECRET, "DECLASSIFY", SINK)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.rule_id, "R-DECLASSIFY-TOKEN")

    def test_untrusted_cannot_be_declassified(self) -> None:
        decision = self.policy.check(BOTH, "DECLASSIFY", SINK)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.rule_id, "R-DECLASSIFY-UNTRUSTED")

    def test_decision_carries_audit_fields(self) -> None:
        payload = self.policy.check(SECRET, "NET", SINK).to_dict()
        self.assertEqual(payload["sink"], SINK)
        self.assertEqual(payload["sink_cap"], "NET")
        self.assertIn("explanation", payload)

    def test_policy_is_loadable_from_json(self) -> None:
        policy = Policy.from_json(DEFAULT_POLICY_JSON)
        self.assertEqual(policy.rule_ids(), self.policy.rule_ids())
        self.assertEqual(policy.version, 1)


class TestApprovalAuthority(unittest.TestCase):
    def setUp(self) -> None:
        self.authority = ApprovalAuthority()
        self.text = "API_KEY: CANARY-0123456789abcdef"

    def test_valid_token_allows_once(self) -> None:
        self.authority.issue("ap1", self.text, SINK, "n1")
        first = self.authority.consume("ap1", self.text, SINK)
        self.assertTrue(first.allowed)
        self.assertEqual(first.rule_id, "R-DECLASS-APPROVED")

    def test_replay_rejected(self) -> None:
        self.authority.issue("ap1", self.text, SINK, "n1")
        self.assertTrue(self.authority.consume("ap1", self.text, SINK).allowed)
        second = self.authority.consume("ap1", self.text, SINK)
        self.assertFalse(second.allowed)
        self.assertEqual(second.rule_id, "R-DECLASS-REPLAY")

    def test_sink_binding_enforced(self) -> None:
        self.authority.issue("ap1", self.text, SINK, "n1")
        decision = self.authority.consume("ap1", self.text, "evil.example")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.rule_id, "R-DECLASS-SINK-MISMATCH")

    def test_value_binding_enforced(self) -> None:
        self.authority.issue("ap1", "other value", SINK, "n1")
        decision = self.authority.consume("ap1", self.text, SINK)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.rule_id, "R-DECLASS-VALUE-MISMATCH")

    def test_unknown_token_rejected(self) -> None:
        decision = self.authority.consume("nope", self.text, SINK)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.rule_id, "R-DECLASS-UNKNOWN-TOKEN")

    def test_token_does_not_survive_value_change(self) -> None:
        self.authority.issue("ap1", self.text, SINK, "n1")
        tampered = self.text + " "
        self.assertFalse(
            self.authority.consume("ap1", tampered, SINK).allowed
        )


class TestLaundering(unittest.TestCase):
    def test_declassify_does_not_raise_integrity(self) -> None:
        mixed = Label(Integrity.UNTRUSTED, Confidentiality.SECRET)
        decision = Policy.default().check(
            declassify(mixed), "NET", SINK
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.rule_id, "R-NET-UNTRUSTED")

    def test_approved_public_value_may_egress(self) -> None:
        decision = Policy.default().check(
            declassify(SECRET), "NET", SINK
        )
        self.assertTrue(decision.allowed)


if __name__ == "__main__":
    unittest.main()
