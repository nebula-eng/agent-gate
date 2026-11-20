"""Render the three evaluation figures from ``results/results.json``.

Every figure is exactly 1600x1000 px (figsize 8x5 in at dpi 200) and uses the
same restrained style, so the three panels can sit next to each other in a
report without visual drift.  Numbers are read from the results file; nothing
is hard-coded, which is what makes the figures reproducible.

The trade-off panel uses a small deterministic horizontal offset for points
that share a coordinate (most configurations reach utility 1.0) and puts the
variant names in a legend rather than next to the markers, because inline
labels collide when six of seven configurations sit on the same vertical.
"""

from __future__ import annotations

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.lines import Line2D  # noqa: E402
from matplotlib.patches import Patch, Rectangle  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results"
FIG_DIR = RESULTS

PALETTE = ["#2b4c7e", "#7a9cc6", "#b0413e", "#c98b3a", "#4f7a5b", "#8b6f9e",
           "#5f6b6d"]

STYLE = {
    "figure.dpi": 200,
    "savefig.dpi": 200,
    "font.family": "serif",
    "font.serif": ["DejaVu Serif"],
    "font.size": 9,
    "axes.labelsize": 9,
    "axes.titlesize": 10,
    "xtick.labelsize": 8,
    "ytick.labelsize": 8,
    "legend.fontsize": 7.5,
    "axes.spines.top": False,
    "axes.spines.right": False,
    "axes.grid": True,
    "grid.alpha": 0.25,
    "grid.linewidth": 0.6,
    "axes.axisbelow": True,
    "legend.frameon": False,
}

SHORT = {
    "direct_inject": "direct\ninject",
    "indirect_file": "indirect\nfile",
    "encoded_exfil": "encoded\nexfil",
    "split_exfil": "split\nexfil",
    "tool_confusion": "tool\nconfusion",
    "legit_declassify_abuse": "declassify\nabuse",
}

VARIANT_LABEL = {
    "full": "full system",
    "no_substring_taint": "no substring taint",
    "no_decode_taint": "no decode taint",
    "no_sink_provenance": "no sink provenance",
    "keyword_filter": "keyword filter",
    "allowlist_only": "allowlist only",
    "no_guard": "no guard",
}


def load() -> dict:
    return json.loads((RESULTS / "results.json").read_text(encoding="utf-8"))


def fig_asr_family(results: dict) -> Path:
    families = list(results["by_family"])
    series = ["full", "keyword_filter", "allowlist_only", "no_guard"]
    matrix = results["variant_by_family"]

    fig, ax = plt.subplots(figsize=(8, 5))
    width = 0.8 / len(series)
    positions = list(range(len(families)))

    for offset, variant in enumerate(series):
        values = [matrix[variant][family] for family in families]
        shifted = [pos + (offset - (len(series) - 1) / 2) * width
                   for pos in positions]
        bars = ax.bar(
            shifted, values, width * 0.92,
            label=None, color=PALETTE[offset],
            edgecolor="white", linewidth=0.5,
        )
        for bar, value in zip(bars, values):
            if value > 0:
                ax.text(bar.get_x() + bar.get_width() / 2,
                        value + 0.015, "%.2f" % value,
                        ha="center", va="bottom", fontsize=6.5,
                        color="#333333")
            elif variant == "full":
                ax.text(bar.get_x() + bar.get_width() / 2, 0.025,
                        "0.00", ha="center", va="bottom", fontsize=6.5,
                        color="#444444",
                        bbox={"facecolor": "white", "edgecolor": "none", "pad": 0.8})

    ax.set_xticks(positions)
    ax.set_xticklabels([SHORT.get(f, f) for f in families])
    ax.set_ylabel("attack success rate (ASR)")
    ax.set_ylim(-0.02, 1.10)
    ax.set_yticks([0, 0.25, 0.5, 0.75, 1.0])
    ax.axhline(0.05, color=PALETTE[2], linestyle=":", linewidth=0.9)

    handles = [Patch(facecolor=PALETTE[index], label=VARIANT_LABEL[name])
               for index, name in enumerate(series)]
    handles.append(Line2D([0], [0], color=PALETTE[2], linestyle=":",
                          linewidth=0.9,
                          label="acceptance bound 0.05"))
    ax.legend(handles=handles, loc="upper center",
              bbox_to_anchor=(0.5, 1.15), ncol=5)
    fig.tight_layout()
    path = FIG_DIR / "fig_asr_family.png"
    fig.savefig(path)
    plt.close(fig)
    return path


def fig_tradeoff(results: dict) -> Path:
    variants = results["variants"]
    names = list(variants)
    fig, ax = plt.subplots(figsize=(8, 5))
    ax.add_patch(Rectangle((0.9, 0.0), 0.14, 0.05, facecolor="#d8e6d8",
                           edgecolor="none", zorder=0))
    ax.text(0.905, 0.008, "target\nregion", ha="left", va="bottom",
            fontsize=6.5, color="#4f7a5b", zorder=1)

    for index, name in enumerate(names):
        row = variants[name]
        # Deterministic jitter: six of seven configurations have utility 1.0,
        # so the column is fanned out by index, never randomly.
        jitter = (index - (len(names) - 1) / 2) * 0.0055
        ax.scatter(row["utility"] + jitter, row["asr"], s=46,
                   color=PALETTE[index % len(PALETTE)],
                   edgecolor="white", linewidth=0.8, zorder=3,
                   label="%s  (%.2f / %.2f)"
                   % (VARIANT_LABEL.get(name, name),
                      row["asr"], row["utility"]))

    ax.set_xlim(0.88, 1.04)
    ax.set_ylim(-0.05, 1.08)
    ax.set_xticks([0.90, 0.95, 1.00])
    ax.set_yticks([0, 0.25, 0.5, 0.75, 1.0])
    ax.set_xlabel("utility (benign tasks completed without leak)")
    ax.set_ylabel("attack success rate (ASR)")
    ax.set_title("Security-utility trade-off by configuration", pad=8)
    ax.legend(loc="upper left", bbox_to_anchor=(0.012, 0.985),
              title="variant  (ASR / utility)", title_fontsize=7.5,
              handletextpad=0.4, borderaxespad=0.2)
    fig.tight_layout()
    path = FIG_DIR / "fig_tradeoff.png"
    fig.savefig(path)
    plt.close(fig)
    return path


def fig_ablation(results: dict) -> Path:
    variants = results["variants"]
    order = ["no_guard", "allowlist_only", "no_substring_taint",
             "keyword_filter", "no_decode_taint", "no_sink_provenance",
             "full"]
    order = [name for name in order if name in variants]
    values = [variants[name]["asr"] for name in order]
    labels = [VARIANT_LABEL.get(name, name) for name in order]

    fig, ax = plt.subplots(figsize=(8, 5))
    colors = [PALETTE[0] if name == "full" else "#9aa5b1" for name in order]
    bars = ax.barh(range(len(order)), values, color=colors,
                   edgecolor="white", linewidth=0.6, height=0.62)
    for bar, value in zip(bars, values):
        ax.text(value + 0.018 if value > 0 else 0.06,
                bar.get_y() + bar.get_height() / 2,
                "%.2f" % value, va="center", fontsize=7.5,
                color="#222222")

    ax.set_yticks(range(len(order)))
    ax.set_yticklabels(labels)
    ax.set_xlim(0, 1.20)
    ax.set_xlabel("attack success rate (ASR) over 60 attacks")
    ax.axvline(0.05, color=PALETTE[2], linestyle=":", linewidth=0.9)
    ax.legend(handles=[Line2D([0], [0], color=PALETTE[2], linestyle=":",
                              linewidth=0.9,
                              label="0.05 acceptance bound")],
              loc="upper right")
    ax.set_title("Ablation: removing one mechanism at a time", pad=8)
    fig.tight_layout()
    path = FIG_DIR / "fig_ablation.png"
    fig.savefig(path)
    plt.close(fig)
    return path


def main() -> int:
    plt.rcParams.update(STYLE)
    results = load()
    FIG_DIR.mkdir(parents=True, exist_ok=True)
    paths = [fig_asr_family(results), fig_tradeoff(results),
             fig_ablation(results)]
    for path in paths:
        print("wrote %s" % path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
