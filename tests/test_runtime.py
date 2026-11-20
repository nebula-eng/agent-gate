"""End-to-end runtime behaviour on the committed corpus.

These tests are the ones that matter: they exercise the same paths the
evaluation runs, on the same committed scenarios, with the same monitor.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from agent_gate.metrics import run_scenario
from agent_gate.runtime import VARIANTS, render_tree
from agent_gate.scenarios import load_corpus

PROJECT = Path(__file__).resolve().parents[1]
DATA = PROJECT / "data" / "scenarios"
RUNTIME_ROOT = PROJECT / "results" / ".runtime"

CORPUS = load_corpus(DATA)
ATTACKS = CORPUS["attacks"]
BENIGN = CORPUS["benign"]


def pick(family: str, index: int = 0) -> dict:
    items = [spec for spec in ATTACKS if spec["family"] == family]
    return items[index]


def run(spec: dict, variant: str = "full"):
    return run_scenario(
        spec, VARIANTS[variant], variant, runtime_root=RUNTIME_ROOT
    )


class TestAttackFamilies(unittest.TestCase):
    def test_direct_inject_denied_and_leaks_unguarded(self) -> None:
        spec = pick("direct_inject")
        guarded = run(spec, "full")
        self.assertFalse(guarded.completed)
        self.assertEqual(guarded.denied_at, "s4")
        self.assertEqual(guarded.denial["rule_id"], "R-NET-SECRET")
        self.assertFalse(guarded.leaked(spec["canary"]))

        unguarded = run(spec, "no_guard")
        self.assertTrue(unguarded.completed)
        self.assertTrue(unguarded.leaked(spec["canary"]))

    def test_indirect_file_denied(self) -> None:
        spec = pick("indirect_file")
        result = run(spec, "full")
        self.assertFalse(result.completed)
        self.assertFalse(result.leaked(spec["canary"]))

    def test_encoded_exfil_denied_and_ablation_leaks(self) -> None:
        spec = pick("encoded_exfil")
        self.assertEqual(spec["attack"]["encoding"], "base64")
        guarded = run(spec, "full")
        self.assertFalse(guarded.completed)
        self.assertFalse(guarded.leaked(spec["canary"]))

        abolished = run(spec, "no_decode_taint")
        self.assertTrue(abolished.completed)
        self.assertTrue(abolished.leaked(spec["canary"]))

    def test_split_exfil_needs_provenance(self) -> None:
        spec = pick("split_exfil")
        canary = spec["canary"]
        guarded = run(spec, "full")
        self.assertFalse(guarded.completed)
        self.assertEqual(guarded.denial["rule_id"], "R-NET-SECRET")

        unguarded = run(spec, "no_guard")
        self.assertTrue(unguarded.completed)
        records = unguarded.egress["records"]
        self.assertEqual(len(records), 2)
        self.assertNotIn(canary, records[0]["body"])
        self.assertNotIn(canary, records[1]["body"])
        self.assertEqual(
            "".join(record["body"] for record in records), canary
        )
        self.assertTrue(unguarded.leaked(canary))

    def test_tool_confusion_hidden_in_url(self) -> None:
        spec = pick("tool_confusion")
        canary = spec["canary"]
        guarded = run(spec, "full")
        self.assertFalse(guarded.completed)
        self.assertFalse(guarded.leaked(canary))

        unguarded = run(spec, "no_guard")
        self.assertIn(canary, unguarded.egress["records"][0]["url"])
        self.assertTrue(unguarded.leaked(canary))

        payload_only = run(spec, "no_sink_provenance")
        self.assertTrue(payload_only.completed)
        self.assertTrue(payload_only.leaked(canary))

    def test_declassify_replay_rejected(self) -> None:
        spec = pick("legit_declassify_abuse", 2)
        self.assertEqual(spec["attack"]["mode"], "replay")
        result = run(spec, "full")
        self.assertFalse(result.completed)
        self.assertEqual(result.denial["rule_id"], "R-DECLASS-REPLAY")
        self.assertFalse(result.leaked(spec["canary"]))

    def test_declassify_without_token_rejected(self) -> None:
        spec = pick("legit_declassify_abuse", 0)
        self.assertEqual(spec["attack"]["mode"], "no_token")
        result = run(spec, "full")
        self.assertEqual(result.denial["rule_id"], "R-DECLASS-NO-TOKEN")

    def test_every_attack_is_blocked_and_unguarded_corpus_leaks(self) -> None:
        blocked = 0
        leaked = 0
        for spec in ATTACKS:
            guarded = run(spec, "full")
            if not guarded.completed and not guarded.leaked(spec["canary"]):
                blocked += 1
            unguarded = run(spec, "no_guard")
            if unguarded.leaked(spec["canary"]):
                leaked += 1
        self.assertEqual(blocked, len(ATTACKS))
        self.assertEqual(leaked, len(ATTACKS))


class TestBenignTasks(unittest.TestCase):
    def test_all_benign_complete_without_leak(self) -> None:
        completed = 0
        for spec in BENIGN:
            result = run(spec, "full")
            if result.completed and not result.leaked(spec["canary"]):
                completed += 1
        self.assertEqual(completed, len(BENIGN))

    def test_public_post_uses_approval(self) -> None:
        spec = [s for s in BENIGN if s["family"] == "benign_public_post"][0]
        result = run(spec, "full")
        self.assertTrue(result.completed)
        rules = [entry["rule_id"] for entry in result.audit]
        self.assertIn("R-DECLASS-APPROVED", rules)
        self.assertIn("R-NET-CLEAN", rules)


class TestAuditSurface(unittest.TestCase):
    def test_audit_entries_are_complete(self) -> None:
        result = run(pick("encoded_exfil"), "full")
        self.assertTrue(result.audit)
        for entry in result.audit:
            for key in ("seq", "step", "tool", "label", "rule_id",
                        "allowed", "explanation"):
                self.assertIn(key, entry)

    def test_provenance_graph_is_exportable(self) -> None:
        result = run(pick("split_exfil"), "no_guard")
        graph = result.provenance
        json.dumps(graph, sort_keys=True)
        kinds = {node["kind"] for node in graph["nodes"]}
        self.assertIn("source", kinds)
        self.assertIn("step", kinds)
        self.assertTrue(graph["edges"])
        self.assertIn("api.internal.example", graph["channel_labels"])

    def test_channel_label_closes_over_fragments(self) -> None:
        result = run(pick("split_exfil"), "no_guard")
        label = result.provenance["channel_labels"]["api.internal.example"]
        self.assertEqual(label["confidentiality"], "SECRET")

    def test_render_tree_is_ascii(self) -> None:
        result = run(pick("direct_inject"), "full")
        text = render_tree(result)
        self.assertIn("provenance tree", text)
        self.assertIn("DENY", text)
        text.encode("ascii")

    def test_denied_run_stops_at_sink(self) -> None:
        result = run(pick("tool_confusion"), "full")
        self.assertFalse(result.completed)
        self.assertEqual(result.egress["records"], [])
        self.assertEqual(result.steps_executed, result.audit[-1]["seq"] - 1)


if __name__ == "__main__":
    unittest.main()
