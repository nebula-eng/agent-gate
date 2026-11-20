"""Declarative policy compiled to a checker, plus the approval authority.

The policy is a JSON document.  Rules are evaluated in order, first match
wins, and every decision carries the rule id that produced it so the audit
log can be replayed by a human without reading code.

Two orthogonal mechanisms live here:

* :class:`Policy` -- the static flow rules.  Given the joined label of a
  call's arguments and the sink capability, it says allow or deny.
* :class:`ApprovalAuthority` -- the only escape hatch for confidentiality.
  A declassification is authorised by a one-shot token bound to
  ``(sha256(value), sink, nonce)``.  The static policy denies every
  declassification; the authority can override exactly one denial, and only
  once per token.

The separation is the point.  A policy that could be talked into allowing a
secret to leave is not a policy; here the secret can only leave if a human
(or an upstream approval system) minted a token that names that exact value
and that exact destination.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field as dc_field
from typing import Any, Mapping

from .labels import Integrity, Label
from .taint import payload_digest

DEFAULT_POLICY_JSON = """{
  "version": 1,
  "default_effect": "allow",
  "rules": [
    {
      "id": "R-NET-UNTRUSTED",
      "when": {"sink_cap": "NET", "integrity": "UNTRUSTED"},
      "effect": "deny",
      "explanation": "untrusted-integrity value may not reach a network sink: injection would become exfiltration"
    },
    {
      "id": "R-NET-SECRET",
      "when": {"sink_cap": "NET", "confidentiality": "SECRET"},
      "effect": "deny",
      "explanation": "secret value may not reach a network sink without a bound declassification token"
    },
    {
      "id": "R-NET-CLEAN",
      "when": {"sink_cap": "NET", "integrity": "TRUSTED", "confidentiality": "PUBLIC"},
      "effect": "allow",
      "explanation": "trusted, public value may egress"
    },
    {
      "id": "R-DECLASSIFY-UNTRUSTED",
      "when": {"sink_cap": "DECLASSIFY", "integrity": "UNTRUSTED"},
      "effect": "deny",
      "explanation": "attacker-controlled content cannot be declassified; an approval does not raise integrity"
    },
    {
      "id": "R-DECLASSIFY-TOKEN",
      "when": {"sink_cap": "DECLASSIFY"},
      "effect": "deny",
      "explanation": "declassification requires an approval token bound to this value and sink"
    },
    {
      "id": "R-DEFAULT-ALLOW",
      "when": {},
      "effect": "allow",
      "explanation": "no rule matched; the flow is not covered by a deny rule"
    }
  ]
}"""


@dataclass(frozen=True)
class Decision:
    """The outcome of one policy evaluation, shaped for the audit log."""

    allowed: bool
    rule_id: str
    explanation: str
    sink: str = ""
    sink_cap: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "rule_id": self.rule_id,
            "explanation": self.explanation,
            "sink": self.sink,
            "sink_cap": self.sink_cap,
        }

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        verdict = "ALLOW" if self.allowed else "DENY"
        return "%s [%s] %s" % (verdict, self.rule_id, self.explanation)


@dataclass(frozen=True)
class Rule:
    id: str
    effect: str
    when: Mapping[str, Any] = dc_field(default_factory=dict)
    explanation: str = ""

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Rule":
        effect = str(data.get("effect", "deny"))
        if effect not in ("allow", "deny"):
            raise ValueError("rule %r has unknown effect %r"
                             % (data.get("id"), effect))
        return cls(
            id=str(data["id"]),
            effect=effect,
            when=dict(data.get("when", {})),
            explanation=str(data.get("explanation", "")),
        )

    def matches(self, label: Label, sink_cap: str, sink_name: str) -> bool:
        when = self.when
        for key, expected in when.items():
            if key == "sink_cap":
                if sink_cap != expected:
                    return False
            elif key == "integrity":
                if label.integrity.value != expected:
                    return False
            elif key == "confidentiality":
                if label.confidentiality.value != expected:
                    return False
            elif key == "capability":
                if expected not in label.capabilities:
                    return False
            elif key == "sink_name":
                if sink_name != expected:
                    return False
            else:
                raise ValueError("rule %r has unknown predicate %r"
                                 % (self.id, key))
        return True


class Policy:
    """A compiled rule list."""

    def __init__(self, spec: Mapping[str, Any]) -> None:
        self.spec = dict(spec)
        self.version = int(spec.get("version", 1))
        self.default_effect = str(spec.get("default_effect", "allow"))
        self.rules: list[Rule] = [
            Rule.from_dict(item) for item in spec.get("rules", [])
        ]

    @classmethod
    def from_json(cls, text: str) -> "Policy":
        return cls(json.loads(text))

    @classmethod
    def default(cls) -> "Policy":
        return cls.from_json(DEFAULT_POLICY_JSON)

    def check(
        self,
        label: Label,
        sink_cap: str,
        sink_name: str = "",
    ) -> Decision:
        for rule in self.rules:
            if rule.matches(label, sink_cap, sink_name):
                return Decision(
                    allowed=rule.effect == "allow",
                    rule_id=rule.id,
                    explanation=rule.explanation,
                    sink=sink_name,
                    sink_cap=sink_cap,
                )
        return Decision(
            allowed=self.default_effect == "allow",
            rule_id="R-DEFAULT",
            explanation="no rule matched; default %s" % self.default_effect,
            sink=sink_name,
            sink_cap=sink_cap,
        )

    def rule_ids(self) -> list[str]:
        return [rule.id for rule in self.rules]


@dataclass(frozen=True)
class Approval:
    """A pre-issued declassification approval."""

    approval_id: str
    value_sha: str
    sink: str
    nonce: str
    used: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "approval_id": self.approval_id,
            "value_sha": self.value_sha,
            "sink": self.sink,
            "nonce": self.nonce,
            "used": self.used,
        }


class ApprovalAuthority:
    """Issues and consumes one-shot declassification tokens.

    Tokens are bound to the exact value digest, the destination sink, and a
    nonce.  Consumption is destructive, so a replayed token is refused.  The
    authority keeps no reference to the value itself, only its digest, which
    is why it can live in the reference monitor without holding secrets.
    """

    def __init__(self) -> None:
        self._approvals: dict[str, Approval] = {}
        self._consumed: set[str] = set()

    # -- issuance (operator side) ---------------------------------------
    def issue(
        self,
        approval_id: str,
        value_text: str,
        sink: str,
        nonce: str,
    ) -> Approval:
        key = (approval_id, sink, nonce)
        if key in self._approvals:
            raise ValueError("approval %r already issued" % approval_id)
        approval = Approval(
            approval_id=approval_id,
            value_sha=payload_digest(value_text),
            sink=sink,
            nonce=nonce,
        )
        self._approvals[approval_id] = approval
        return approval

    def revoke(self, approval_id: str) -> None:
        self._approvals.pop(approval_id, None)

    # -- consumption (monitor side) -------------------------------------
    def consume(self, approval_id: str, value_text: str, sink: str) -> Decision:
        approval = self._approvals.get(approval_id)
        if approval is None:
            return Decision(
                allowed=False,
                rule_id="R-DECLASS-UNKNOWN-TOKEN",
                explanation="no approval token with this id was issued",
                sink=sink,
                sink_cap="DECLASSIFY",
            )
        if approval_id in self._consumed:
            return Decision(
                allowed=False,
                rule_id="R-DECLASS-REPLAY",
                explanation="approval token was already consumed; tokens are one-shot",
                sink=sink,
                sink_cap="DECLASSIFY",
            )
        if approval.sink != sink:
            return Decision(
                allowed=False,
                rule_id="R-DECLASS-SINK-MISMATCH",
                explanation="approval token is bound to sink %r, not %r"
                % (approval.sink, sink),
                sink=sink,
                sink_cap="DECLASSIFY",
            )
        digest = payload_digest(value_text)
        if digest != approval.value_sha:
            return Decision(
                allowed=False,
                rule_id="R-DECLASS-VALUE-MISMATCH",
                explanation="approval token is bound to a different value digest",
                sink=sink,
                sink_cap="DECLASSIFY",
            )
        self._consumed.add(approval_id)
        return Decision(
            allowed=True,
            rule_id="R-DECLASS-APPROVED",
            explanation="one-shot approval token matched value digest and sink",
            sink=sink,
            sink_cap="DECLASSIFY",
        )

    # -- introspection ---------------------------------------------------
    def pending(self) -> list[Approval]:
        return [
            approval
            for key, approval in sorted(self._approvals.items())
            if key not in self._consumed
        ]

    def to_dict(self) -> dict[str, Any]:
        return {
            "issued": [approval.to_dict()
                       for _, approval in sorted(self._approvals.items())],
            "consumed": sorted(self._consumed),
        }


def deny_unless_public(label: Label, sink_cap: str,
                       sink_name: str = "") -> Decision:
    """Convenience helper used by tests and by custom policies."""
    if label.integrity is Integrity.TRUSTED and label.confidentiality.value == "PUBLIC":
        return Decision(True, "HELPER-ALLOW", "label is trusted and public",
                        sink_name, sink_cap)
    return Decision(False, "HELPER-DENY", "label is not trusted public",
                    sink_name, sink_cap)
