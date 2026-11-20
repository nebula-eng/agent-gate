"""Command line interface: ``gen``, ``eval``, ``demo``, ``audit``."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

from .metrics import (
    evaluate,
    format_table,
    measure_policy_overhead,
    run_scenario,
    write_results,
)
from .runtime import VARIANTS, render_tree
from .scenarios import (
    ATTACK_FAMILIES,
    CORPUS_SEED,
    generate,
    load_corpus,
    save_corpus,
    verify_committed,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DATA_DIR = PROJECT_ROOT / "data" / "scenarios"
DEFAULT_RESULTS_DIR = PROJECT_ROOT / "results"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _load(data_dir: Path) -> dict[str, Any]:
    corpus = load_corpus(data_dir)
    return {
        "seed": corpus["seed"],
        "attacks": list(corpus["attacks"]),
        "benign": list(corpus["benign"]),
        "families": list(corpus["families"]),
        "benign_kinds": list(corpus["benign_kinds"]),
    }


def _find(specs: Sequence[Mapping[str, Any]], ident: str) -> Mapping[str, Any]:
    for spec in specs:
        if spec["id"] == ident:
            return spec
    raise SystemExit("no scenario with id %r" % ident)


def _print_audit(result, title: str) -> None:
    print(title)
    for entry in result.audit:
        verdict = "allow" if entry["allowed"] else "DENY "
        print("  %-3s %-10s %-5s %-22s %s" % (
            entry["step"], entry["tool"], verdict, entry["rule_id"],
            entry["explanation"][:64],
        ))
    records = result.egress.get("records", [])
    print("  egress: %d request(s), %d byte(s)"
          % (len(records), result.egress.get("total_bytes", 0)))
    for record in records:
        print("    -> %s  body=%r" % (record["url"], record["body"][:48]))


# ---------------------------------------------------------------------------
# subcommands
# ---------------------------------------------------------------------------
def cmd_gen(args: argparse.Namespace) -> int:
    data_dir = Path(args.data_dir)
    if args.check:
        ok, message = verify_committed(data_dir, args.seed)
        print(("ok: " if ok else "drift: ") + message)
        return 0 if ok else 1
    corpus = generate(args.seed)
    attacks_path, benign_path = save_corpus(corpus, data_dir)
    print("wrote %s (%d scenarios)"
          % (attacks_path, len(corpus["attacks"])))
    print("wrote %s (%d scenarios)"
          % (benign_path, len(corpus["benign"])))
    for family in ATTACK_FAMILIES:
        count = sum(1 for item in corpus["attacks"]
                    if item["family"] == family)
        print("  %-24s %d" % (family, count))
    return 0


def cmd_eval(args: argparse.Namespace) -> int:
    data_dir = Path(args.data_dir)
    results_dir = Path(args.results_dir)
    ok, message = verify_committed(data_dir, CORPUS_SEED)
    if not ok:
        print("corpus drift: %s (run `agent-gate gen`)" % message,
              file=sys.stderr)
        return 2
    corpus = _load(data_dir)
    results = evaluate(corpus, data_dir,
                       runtime_root=results_dir / ".runtime")
    out = write_results(results, results_dir / "results.json")
    timing = measure_policy_overhead(iterations=args.timing_iterations)
    (results_dir / "timing.json").write_text(
        json.dumps(timing, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(format_table(results))
    print("")
    print("policy check overhead: p50=%.3f us p95=%.3f us"
          % (timing["p50_us"], timing["p95_us"]))
    print("wrote %s" % out)
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    corpus = _load(Path(args.data_dir))
    spec = _find(corpus["attacks"], args.scenario)
    print("scenario: %s  family=%s" % (spec["id"], spec["family"]))
    print("canary:   %s" % spec["canary"])
    print("")
    for variant in ("no_guard", "full"):
        result = run_scenario(
            spec, VARIANTS[variant], variant,
            runtime_root=Path(args.results_dir) / ".runtime",
        )
        _print_audit(result,
                     "== %s ==" % variant)
        print("  leaked: %s" % ("YES" if result.leaked(spec["canary"])
                                else "no"))
        print("")
    if args.audit:
        result = run_scenario(
            spec, VARIANTS["full"], "full",
            runtime_root=Path(args.results_dir) / ".runtime",
        )
        print(render_tree(result))
        print("")
        print(json.dumps(result.provenance, indent=2, sort_keys=True)[:1200])
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    corpus = _load(Path(args.data_dir))
    specs = list(corpus["attacks"]) + list(corpus["benign"])
    spec = _find(specs, args.scenario)
    config = VARIANTS[args.variant]
    result = run_scenario(
        spec, config, args.variant,
        runtime_root=Path(args.results_dir) / ".runtime",
    )
    print(render_tree(result))
    print("")
    print("decisions:")
    for entry in result.audit:
        print("  %-3s %-10s %-5s %-24s label=%s" % (
            entry["step"], entry["tool"],
            "allow" if entry["allowed"] else "DENY",
            entry["rule_id"],
            entry["label"],
        ))
    return 0


# ---------------------------------------------------------------------------
# parser
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agent-gate",
        description="Capability-taint isolation for LLM tool-calling agents.",
    )
    parser.add_argument("--data-dir", default=str(DEFAULT_DATA_DIR))
    parser.add_argument("--results-dir", default=str(DEFAULT_RESULTS_DIR))
    sub = parser.add_subparsers(dest="command", required=True)

    gen = sub.add_parser("gen", help="regenerate the committed corpus")
    gen.add_argument("--seed", type=int, default=CORPUS_SEED)
    gen.add_argument("--check", action="store_true",
                     help="verify the committed JSON instead of writing")
    gen.set_defaults(func=cmd_gen)

    ev = sub.add_parser("eval", help="run the corpus and write results.json")
    ev.add_argument("--timing-iterations", type=int, default=4000)
    ev.set_defaults(func=cmd_eval)

    demo = sub.add_parser("demo", help="show one scenario with and without guard")
    demo.add_argument("--scenario", default="att-encoded_exfil-00")
    demo.add_argument("--audit", action="store_true",
                      help="also print the provenance tree")
    demo.set_defaults(func=cmd_demo)

    audit = sub.add_parser("audit", help="print the provenance tree")
    audit.add_argument("--scenario", required=True)
    audit.add_argument("--variant", default="full", choices=sorted(VARIANTS))
    audit.set_defaults(func=cmd_audit)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
