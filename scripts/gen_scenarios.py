"""Regenerate ``data/scenarios/*.json`` from the deterministic generator.

Usage:
    python scripts/gen_scenarios.py [--seed 1337] [--check]

The generator is pure: identical seed in, identical bytes out.  ``--check``
re-derives the corpus and compares it with the committed files, which is what
``make eval`` runs before trusting any number.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agent_gate.scenarios import CORPUS_SEED, generate, save_corpus, verify_committed  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=CORPUS_SEED)
    parser.add_argument("--data-dir", default=str(ROOT / "data" / "scenarios"))
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)

    data_dir = Path(args.data_dir)
    if args.check:
        ok, message = verify_committed(data_dir, args.seed)
        print(("ok: " if ok else "drift: ") + message)
        return 0 if ok else 1

    corpus = generate(args.seed)
    attacks_path, benign_path = save_corpus(corpus, data_dir)
    print("wrote %s (%d attacks)" % (attacks_path, len(corpus["attacks"])))
    print("wrote %s (%d benign)" % (benign_path, len(corpus["benign"])))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
