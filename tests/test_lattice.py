"""Lattice laws: the algebra the whole mechanism rests on.

The properties are re-derived over a sampled subset of the label space rather
than assumed from the product construction, because an ordering bug here is
silent: every policy decision would still return a verdict, just the wrong
one.
"""

from __future__ import annotations

import random
import unittest

from agent_gate.labels import CAPABILITIES, Confidentiality, Integrity, Label
from agent_gate.lattice import (
    BOTTOM,
    TOP,
    declassify,
    join,
    join_all,
    join_table,
    leq,
    meet,
)


def sample_labels(count: int = 64) -> list[Label]:
    rng = random.Random(1337)
    caps = sorted(CAPABILITIES)
    labels: list[Label] = []
    for _ in range(count):
        chosen = frozenset(
            cap for cap in caps if rng.random() < 0.35
        )
        labels.append(
            Label(
                rng.choice([Integrity.TRUSTED, Integrity.UNTRUSTED]),
                rng.choice([Confidentiality.PUBLIC, Confidentiality.SECRET]),
                chosen,
            )
        )
    return labels


class TestLatticeLaws(unittest.TestCase):
    def setUp(self) -> None:
        self.labels = sample_labels()

    def test_join_idempotent(self) -> None:
        for label in self.labels:
            self.assertEqual(join(label, label), label)

    def test_join_commutative(self) -> None:
        for a in self.labels:
            for b in self.labels[:16]:
                self.assertEqual(join(a, b), join(b, a))

    def test_join_associative(self) -> None:
        for a in self.labels[:8]:
            for b in self.labels[8:16]:
                for c in self.labels[16:24]:
                    self.assertEqual(
                        join(join(a, b), c), join(a, join(b, c))
                    )

    def test_meet_associative(self) -> None:
        for a in self.labels[:6]:
            for b in self.labels[6:12]:
                for c in self.labels[12:18]:
                    self.assertEqual(
                        meet(meet(a, b), c), meet(a, meet(b, c))
                    )

    def test_absorption(self) -> None:
        for a in self.labels[:12]:
            for b in self.labels[12:24]:
                self.assertEqual(join(a, meet(a, b)), a)
                self.assertEqual(meet(a, join(a, b)), a)

    def test_join_is_upper_bound(self) -> None:
        for a in self.labels[:10]:
            for b in self.labels[10:20]:
                joined = join(a, b)
                self.assertTrue(leq(a, joined))
                self.assertTrue(leq(b, joined))

    def test_meet_is_lower_bound(self) -> None:
        for a in self.labels[:10]:
            for b in self.labels[10:20]:
                lowered = meet(a, b)
                self.assertTrue(leq(lowered, a))
                self.assertTrue(leq(lowered, b))

    def test_order_reflexive_and_transitive(self) -> None:
        for a in self.labels[:12]:
            self.assertTrue(leq(a, a))
        for a in self.labels[:5]:
            for b in self.labels[5:10]:
                for c in self.labels[10:15]:
                    if leq(a, b) and leq(b, c):
                        self.assertTrue(leq(a, c))

    def test_bottom_and_top(self) -> None:
        for label in self.labels:
            self.assertTrue(leq(BOTTOM, label))
            self.assertTrue(leq(label, TOP))
            self.assertEqual(join(BOTTOM, label), label)
            self.assertEqual(meet(TOP, label), label)

    def test_join_all_matches_fold(self) -> None:
        for size in range(1, 6):
            subset = self.labels[:size]
            self.assertEqual(join_all(subset), join_all(subset[::-1]))


class TestLabelDomain(unittest.TestCase):
    def test_unknown_capability_rejected(self) -> None:
        with self.assertRaises(ValueError):
            Label(capabilities={"NETWROK"})

    def test_roundtrip(self) -> None:
        label = Label(
            Integrity.UNTRUSTED, Confidentiality.SECRET, frozenset({"NET"})
        )
        self.assertEqual(Label.from_dict(label.to_dict()), label)

    def test_declassify_drops_confidentiality_only(self) -> None:
        secret = Label(Integrity.UNTRUSTED, Confidentiality.SECRET)
        result = declassify(secret)
        self.assertEqual(result.confidentiality, Confidentiality.PUBLIC)
        self.assertEqual(result.integrity, Integrity.UNTRUSTED)
        self.assertTrue(leq(result, secret))

    def test_untrusted_join_propagates(self) -> None:
        clean = Label()
        dirty = Label(Integrity.UNTRUSTED, Confidentiality.PUBLIC)
        self.assertEqual(join(clean, dirty).integrity, Integrity.UNTRUSTED)

    def test_product_order_has_incomparable_points(self) -> None:
        # A product of two chains is a partial order, not a chain: trusted
        # secret and untrusted public are incomparable, which is precisely
        # why the policy needs a rule per dimension.
        secret = Label(confidentiality=Confidentiality.SECRET)
        dirty = Label(integrity=Integrity.UNTRUSTED)
        self.assertFalse(leq(secret, dirty))
        self.assertFalse(leq(dirty, secret))
        self.assertEqual(join(secret, dirty),
                         Label(Integrity.UNTRUSTED,
                               Confidentiality.SECRET))

    def test_capabilities_make_order_partial(self) -> None:
        only_net = Label(capabilities=frozenset({"NET"}))
        no_caps = Label()
        self.assertTrue(leq(no_caps, only_net))
        self.assertFalse(leq(only_net, no_caps))
        with_fs = Label(capabilities=frozenset({"FS_WRITE"}))
        self.assertFalse(leq(only_net, with_fs))
        self.assertFalse(leq(with_fs, only_net))

    def test_join_table_renders(self) -> None:
        table = join_table()
        self.assertIn("T/P", table)
        self.assertEqual(len(table.splitlines()), 6)


if __name__ == "__main__":
    unittest.main()
