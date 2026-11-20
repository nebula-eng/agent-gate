"""Evaluation: run the corpus under a set of guard configurations.

Two invariants make the numbers trustworthy:

* the leak predicate is byte-exact (see ``taint.detect_leak``), so a success
  cannot be an artefact of a fuzzy similarity threshold;
* every configuration is run over the same committed plans, so the only
  variable between rows is the mechanism under test.

Wall-clock timings are deliberately excluded from ``results.json``: the
deterministic tables must be bit-identical across machines, and a microsecond
figure never is.  Timing lands in ``results/timing.json`` instead.
"""

from __future__ import annotations

import json
import shutil
import statistics
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from .backends import build_plan
from .labels import Confidentiality, Integrity, Label
from .policy import Policy
from .runtime import GuardConfig, RunResult, Runtime, VARIANTS
from .scenarios import authority_for, corpus_digest, pages_for
from .tools import EgressRecorder, Sandbox, Tools, drop_runtime_dir, make_runtime_dir

__all__ = [
    "evaluate",
    "measure_policy_overhead",
    "run_scenario",
    "write_results",
]


def _label(value: Integrity, confidentiality: Confidentiality) -> Label:
    return Label(value, confidentiality)


def run_scenario(
    spec: Mapping[str, Any],
    config: GuardConfig,
    variant: str = "full",
    policy: Policy | None = None,
    runtime_root: Path | str | None = None,
    scratch: Path | str | None = None,
) -> RunResult:
    """Materialise the sandbox, build the plan, execute it under the monitor.

    ``scratch`` lets the evaluator reuse one directory for hundreds of runs.
    Creating and deleting a temporary tree per run dominates the wall clock
    on Windows and buys nothing: every run rewrites the files it declares, so
    a reused directory is observationally identical to a fresh one.
    """
    if scratch is not None:
        root = Path(scratch)
        root.mkdir(parents=True, exist_ok=True)
        keep = True
    elif runtime_root is not None:
        root = make_runtime_dir(Path(runtime_root))
        keep = False
    else:
        import tempfile

        root = Path(tempfile.mkdtemp(prefix="agent-gate-"))
        keep = False
    try:
        sandbox = Sandbox(root, {})
        for item in spec.get("files", []):
            sandbox.add(
                item["path"],
                item["content"],
                Label(
                    Integrity(item["integrity"]),
                    Confidentiality(item["confidentiality"]),
                ),
            )
        egress = EgressRecorder()
        tools = Tools(sandbox, egress, pages_for(spec))
        runtime = Runtime(
            tools=tools,
            policy=policy or Policy.default(),
            config=config,
            authority=authority_for(spec),
            variant=variant,
        )
        return runtime.run(build_plan(spec))
    finally:
        if not keep:
            drop_runtime_dir(root)


def _rate(numerator: int, denominator: int) -> float:
    if denominator <= 0:
        return 0.0
    return round(numerator / denominator, 4)


@dataclass
class VariantOutcome:
    name: str
    attack_leaks: int = 0
    attack_total: int = 0
    benign_ok: int = 0
    benign_total: int = 0
    benign_denied: int = 0
    per_family: dict[str, list[int]] | None = None
    rules: dict[str, int] | None = None
    denied_steps: dict[str, int] | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "asr": _rate(self.attack_leaks, self.attack_total),
            "utility": _rate(self.benign_ok, self.benign_total),
            "fpr": _rate(self.benign_denied, self.benign_total),
            "attacks": self.attack_total,
            "leaks": self.attack_leaks,
            "benign": self.benign_total,
            "benign_completed": self.benign_ok,
            "benign_denied": self.benign_denied,
        }


def evaluate(
    corpus: Mapping[str, Any],
    data_dir: Path | str,
    variants: Mapping[str, GuardConfig] | None = None,
    runtime_root: Path | str | None = None,
) -> dict[str, Any]:
    variants = dict(variants or VARIANTS)
    attacks: Sequence[Mapping[str, Any]] = corpus["attacks"]
    benign: Sequence[Mapping[str, Any]] = corpus["benign"]
    policy = Policy.default()

    scratch_root = Path(runtime_root) if runtime_root else None
    outcomes: dict[str, VariantOutcome] = {}
    for name, config in variants.items():
        scratch = None
        if scratch_root is not None:
            scratch = scratch_root / ("scratch-%s" % name)
        outcome = VariantOutcome(
            name=name,
            attack_total=len(attacks),
            benign_total=len(benign),
            per_family={family: [0, 0] for family in corpus["families"]},
            rules={},
            denied_steps={},
        )
        for spec in attacks:
            result = run_scenario(
                spec, config, name, policy, scratch=scratch
            )
            family = spec["family"]
            outcome.per_family[family][1] += 1
            if result.leaked(spec["canary"]):
                outcome.attack_leaks += 1
                outcome.per_family[family][0] += 1
            for entry in result.audit:
                if not entry["allowed"]:
                    rule = entry["rule_id"]
                    outcome.rules[rule] = outcome.rules.get(rule, 0) + 1
                    step = entry["step"]
                    outcome.denied_steps[step] = (
                        outcome.denied_steps.get(step, 0) + 1
                    )
        for spec in benign:
            result = run_scenario(
                spec, config, name, policy, scratch=scratch
            )
            leaked = result.leaked(spec.get("canary"))
            if result.completed and not leaked:
                outcome.benign_ok += 1
            if not result.completed:
                outcome.benign_denied += 1
        outcomes[name] = outcome

    if scratch_root is not None:
        for name in variants:
            shutil.rmtree(scratch_root / ("scratch-%s" % name),
                          ignore_errors=True)

    full = outcomes.get("full") or next(iter(outcomes.values()))
    by_family: dict[str, Any] = {}
    for family, (leaks, total) in full.per_family.items():
        by_family[family] = {
            "n": total,
            "leaks": leaks,
            "asr": _rate(leaks, total),
        }

    variant_table = {
        name: outcome.as_dict() for name, outcome in outcomes.items()
    }
    variant_by_family = {
        name: {
            family: _rate(leaks, total)
            for family, (leaks, total) in (outcome.per_family or {}).items()
        }
        for name, outcome in outcomes.items()
    }

    results: dict[str, Any] = {
        "schema": 1,
        "corpus": {
            "attacks": len(attacks),
            "benign": len(benign),
            "seed": corpus.get("seed"),
            "families": list(corpus["families"]),
            "benign_kinds": list(corpus.get("benign_kinds", [])),
            "sha256": corpus_digest(("attacks.json", "benign.json"), data_dir),
        },
        "summary": {
            "asr": variant_table["full"]["asr"],
            "utility": variant_table["full"]["utility"],
            "fpr": variant_table["full"]["fpr"],
            "attacks": len(attacks),
            "leaks": variant_table["full"]["leaks"],
            "benign": len(benign),
            "benign_completed": variant_table["full"]["benign_completed"],
            "benign_denied": variant_table["full"]["benign_denied"],
        },
        "by_family": by_family,
        "variants": variant_table,
        "variant_by_family": variant_by_family,
        "full_violations": dict(sorted((full.rules or {}).items())),
        "full_blocked_steps": dict(sorted((full.denied_steps or {}).items())),
    }
    return results


def measure_policy_overhead(
    policy: Policy | None = None,
    iterations: int = 2000,
) -> dict[str, Any]:
    """Median and p95 wall-clock cost of a single policy evaluation."""
    policy = policy or Policy.default()
    cases = [
        (_label(Integrity.TRUSTED, Confidentiality.PUBLIC), "FS_READ", "notes"),
        (_label(Integrity.UNTRUSTED, Confidentiality.PUBLIC), "NET", "evil"),
        (_label(Integrity.TRUSTED, Confidentiality.SECRET), "NET", "evil"),
        (_label(Integrity.UNTRUSTED, Confidentiality.SECRET), "LLM", "model"),
    ]
    samples: list[float] = []
    for _ in range(max(1, iterations // len(cases))):
        for label, cap, sink in cases:
            start = time.perf_counter_ns()
            policy.check(label, cap, sink)
            samples.append((time.perf_counter_ns() - start) / 1000.0)
    samples.sort()
    p50 = statistics.median(samples)
    index = min(len(samples) - 1, int(round(0.95 * (len(samples) - 1))))
    return {
        "iterations": len(samples),
        "p50_us": round(p50, 3),
        "p95_us": round(samples[index], 3),
        "min_us": round(samples[0], 3),
        "max_us": round(samples[-1], 3),
        "note": "machine dependent; excluded from the deterministic results",
    }


def write_results(results: Mapping[str, Any], path: Path | str) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(results, indent=2, sort_keys=True, ensure_ascii=True)
    path.write_text(text + "\n", encoding="utf-8", newline="\n")
    return path


def format_table(results: Mapping[str, Any]) -> str:
    """Human-readable summary used by ``agent-gate eval``."""
    summary = results["summary"]
    lines = [
        "corpus: %d attacks, %d benign, seed=%s"
        % (summary["attacks"], summary["benign"], results["corpus"]["seed"]),
        "",
        "full system",
        "  ASR       %.4f  (%d/%d)"
        % (summary["asr"], summary["leaks"], summary["attacks"]),
        "  utility   %.4f  (%d/%d)"
        % (summary["utility"], summary["benign_completed"], summary["benign"]),
        "  FPR       %.4f  (%d/%d)"
        % (summary["fpr"], summary["benign_denied"], summary["benign"]),
        "",
        "ASR by family",
    ]
    for family, row in results["by_family"].items():
        lines.append("  %-24s %.4f  (%d/%d)"
                     % (family, row["asr"], row["leaks"], row["n"]))
    lines.append("")
    lines.append("variants")
    lines.append("  %-22s %8s %8s %8s" % ("variant", "ASR", "utility", "FPR"))
    for name, row in results["variants"].items():
        lines.append("  %-22s %8.4f %8.4f %8.4f"
                     % (name, row["asr"], row["utility"], row["fpr"]))
    return "\n".join(lines)
