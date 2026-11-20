"""Security labels for agent-gate.

A label is a point in the product lattice

    Integrity x Confidentiality x P(Capabilities)

where ``Integrity`` and ``Confidentiality`` are two-element chains and
``Capabilities`` is a powerset ordered by inclusion.  The lattice itself
(join, meet, order) lives in :mod:`agent_gate.lattice`; this module owns the
value domain and its (de)serialization so that labels can be written to JSON
audit logs without loss.

The dataclass is frozen and validates its capability set at construction
time.  Validation is deliberate: a typo such as ``"NETWROK"`` would silently
produce a capability that no sink ever intersects, i.e. a fail-open bug.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping


#: Capabilities understood by the reference tool set.  Extending this set is
#: a configuration change, not a policy change: the lattice is parametric in
#: the capability universe.
CAPABILITIES = frozenset(
    {
        "NET",        # network egress: the only capability the policy treats
                      # as a sink for exfiltration
        "NET_IN",     # network ingress: a source, never a sink
        "FS_READ",    # sandbox file read
        "FS_WRITE",   # sandbox file write
        "LLM",        # data leaves the process into a model
        "DECLASSIFY", # explicit, approved confidentiality downgrade
        "NONE",       # pure computation
    }
)


class Integrity(str, Enum):
    """Trust in the *origin* of a value.

    ``TRUSTED``   value was produced by the operator, the local sandbox, or
                  deterministic code the operator controls.
    ``UNTRUSTED`` value transited a channel an attacker can write to (web
                  page, mail body, third-party file, tool output).
    """

    TRUSTED = "TRUSTED"
    UNTRUSTED = "UNTRUSTED"

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        return self.value


class Confidentiality(str, Enum):
    """Sensitivity of a value's *content*."""

    PUBLIC = "PUBLIC"
    SECRET = "SECRET"

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        return self.value


INTEGRITY_RANK: Mapping[Integrity, int] = {
    Integrity.TRUSTED: 0,
    Integrity.UNTRUSTED: 1,
}
CONFIDENTIALITY_RANK: Mapping[Confidentiality, int] = {
    Confidentiality.PUBLIC: 0,
    Confidentiality.SECRET: 1,
}
INTEGRITY_BY_RANK = {rank: value for value, rank in INTEGRITY_RANK.items()}
CONFIDENTIALITY_BY_RANK = {rank: value for value, rank in CONFIDENTIALITY_RANK.items()}


def _coerce_enum(enum_cls: Any, value: Any) -> Any:
    if isinstance(value, enum_cls):
        return value
    return enum_cls(str(value))


@dataclass(frozen=True)
class Label:
    """An element of the label lattice.

    Ordering (see :func:`agent_gate.lattice.leq`): ``a <= b`` iff ``a`` is at
    least as restrictive as ``b`` on every component, i.e. ``a.integrity`` is
    at most as untrusted, ``a.confidentiality`` at most as secret, and
    ``a.capabilities`` is a subset of ``b.capabilities``.
    """

    integrity: Integrity = Integrity.TRUSTED
    confidentiality: Confidentiality = Confidentiality.PUBLIC
    capabilities: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        integrity = _coerce_enum(Integrity, self.integrity)
        confidentiality = _coerce_enum(Confidentiality, self.confidentiality)
        capabilities = frozenset(self.capabilities)
        unknown = capabilities - CAPABILITIES
        if unknown:
            raise ValueError(
                "unknown capability: %s" % ", ".join(sorted(unknown))
            )
        object.__setattr__(self, "integrity", integrity)
        object.__setattr__(self, "confidentiality", confidentiality)
        object.__setattr__(self, "capabilities", capabilities)

    # -- serialization ---------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        return {
            "integrity": self.integrity.value,
            "confidentiality": self.confidentiality.value,
            "capabilities": sorted(self.capabilities),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Label":
        return cls(
            integrity=Integrity(data.get("integrity", "TRUSTED")),
            confidentiality=Confidentiality(
                data.get("confidentiality", "PUBLIC")
            ),
            capabilities=frozenset(data.get("capabilities", ())),
        )

    # -- ergonomics ------------------------------------------------------
    def with_capabilities(self, *caps: str) -> "Label":
        return Label(
            integrity=self.integrity,
            confidentiality=self.confidentiality,
            capabilities=self.capabilities | frozenset(caps),
        )

    def is_public_trusted(self) -> bool:
        return (
            self.integrity is Integrity.TRUSTED
            and self.confidentiality is Confidentiality.PUBLIC
        )

    def __str__(self) -> str:
        caps = ",".join(sorted(self.capabilities)) or "-"
        return "I=%s C=%s caps={%s}" % (
            self.integrity.value,
            self.confidentiality.value,
            caps,
        )
