"""The label lattice: join (least upper bound), meet, and the order.

Both component chains are oriented so that the *more permissive* element is
larger:

    TRUSTED  <= UNTRUSTED      (public trust is the bottom)
    PUBLIC   <= SECRET
    {}       <= {NET} <= {NET, FS_WRITE} ...

``join`` is therefore componentwise max/set-union, and ``leq`` is
componentwise <=/subset.  The join is the natural operation for data flow:
the result of combining values must be at least as restrictive as every
input, so no derivation can launder a label.

The product of lattices is a lattice, so idempotence, commutativity,
associativity, and absorption hold by construction; the tests re-derive them
numerically over a randomly sampled subset rather than trusting the algebra.

Every function here is total and returns a fresh frozen ``Label``; there is
no mutation anywhere in the lattice layer.
"""

from __future__ import annotations

from typing import Iterable, Iterator

from .labels import (
    CONFIDENTIALITY_BY_RANK,
    CONFIDENTIALITY_RANK,
    INTEGRITY_BY_RANK,
    INTEGRITY_RANK,
    Confidentiality,
    Integrity,
    Label,
)

BOTTOM = Label(
    integrity=Integrity.TRUSTED,
    confidentiality=Confidentiality.PUBLIC,
    capabilities=frozenset(),
)

TOP = Label(
    integrity=Integrity.UNTRUSTED,
    confidentiality=Confidentiality.SECRET,
    capabilities=frozenset(
        {"NET", "NET_IN", "FS_READ", "FS_WRITE", "LLM", "DECLASSIFY", "NONE"}
    ),
)


def join(a: Label, b: Label) -> Label:
    """Least upper bound of two labels."""
    integrity = INTEGRITY_BY_RANK[max(
        INTEGRITY_RANK[a.integrity], INTEGRITY_RANK[b.integrity]
    )]
    confidentiality = CONFIDENTIALITY_BY_RANK[max(
        CONFIDENTIALITY_RANK[a.confidentiality],
        CONFIDENTIALITY_RANK[b.confidentiality],
    )]
    return Label(
        integrity=integrity,
        confidentiality=confidentiality,
        capabilities=a.capabilities | b.capabilities,
    )


def meet(a: Label, b: Label) -> Label:
    """Greatest lower bound of two labels."""
    integrity = INTEGRITY_BY_RANK[min(
        INTEGRITY_RANK[a.integrity], INTEGRITY_RANK[b.integrity]
    )]
    confidentiality = CONFIDENTIALITY_BY_RANK[min(
        CONFIDENTIALITY_RANK[a.confidentiality],
        CONFIDENTIALITY_RANK[b.confidentiality],
    )]
    return Label(
        integrity=integrity,
        confidentiality=confidentiality,
        capabilities=a.capabilities & b.capabilities,
    )


def leq(a: Label, b: Label) -> bool:
    """True iff ``a <= b`` in the lattice order (``b`` dominates ``a``)."""
    return (
        INTEGRITY_RANK[a.integrity] <= INTEGRITY_RANK[b.integrity]
        and CONFIDENTIALITY_RANK[a.confidentiality]
        <= CONFIDENTIALITY_RANK[b.confidentiality]
        and a.capabilities <= b.capabilities
    )


def join_all(labels: Iterable[Label], start: Label = BOTTOM) -> Label:
    acc = start
    for label in labels:
        acc = join(acc, label)
    return acc


def declassify(label: Label) -> Label:
    """Drop confidentiality to PUBLIC, preserving integrity and capabilities.

    Integrity is deliberately *not* raised.  A declassification approval lets
    a value leave the organisation; it does not make attacker-controlled bytes
    trustworthy, so an approved dump of an untrusted page is still refused at
    a network sink by the integrity rule.
    """
    return Label(
        integrity=label.integrity,
        confidentiality=Confidentiality.PUBLIC,
        capabilities=label.capabilities,
    )


def universe(capability_names: Iterable[str]) -> Iterator[Label]:
    """Enumerate all labels over a small capability universe (docs/tests)."""
    from itertools import combinations

    caps = sorted(set(capability_names))
    for size in range(len(caps) + 1):
        for combo in combinations(caps, size):
            for integrity in (Integrity.TRUSTED, Integrity.UNTRUSTED):
                for confidentiality in (
                    Confidentiality.PUBLIC,
                    Confidentiality.SECRET,
                ):
                    yield Label(integrity, confidentiality, frozenset(combo))


def join_table() -> str:
    """Markdown join table over the four integrity/confidentiality points."""
    points = [
        Label(Integrity.TRUSTED, Confidentiality.PUBLIC),
        Label(Integrity.TRUSTED, Confidentiality.SECRET),
        Label(Integrity.UNTRUSTED, Confidentiality.PUBLIC),
        Label(Integrity.UNTRUSTED, Confidentiality.SECRET),
    ]
    short = ["T/P", "T/S", "U/P", "U/S"]
    lines = ["| join | " + " | ".join(short) + " |",
             "|---|" + "---|" * len(short)]
    for i, row_label in enumerate(points):
        cells = []
        for col_label in points:
            joined = join(row_label, col_label)
            idx = points.index(
                Label(joined.integrity, joined.confidentiality)
            )
            cells.append(short[idx])
        lines.append("| **%s** | %s |" % (short[i], " | ".join(cells)))
    return "\n".join(lines)
