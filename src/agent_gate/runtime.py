"""The reference monitor: plan execution with mandatory flow checks.

Runtime responsibilities, in order, for every step:

1. resolve argument expressions into ``Tainted`` values (references to
   earlier outputs, concatenation, slicing, field extraction, encoding);
2. join the labels and provenance of all arguments;
3. compute the sink name (the URL host for network sinks) and, for sinks
   that accumulate state, join the channel label -- this is the provenance
   closure that catches split exfiltration;
4. ask the policy, before the call, and record the decision;
5. execute the tool, or raise :class:`PolicyViolation`.

The monitor never inspects argument *content* for policy purposes.  Content
inspection exists only in the deliberately weak baselines, because a monitor
that can be fooled by encoding is not a monitor.
"""

from __future__ import annotations

import urllib.parse
from dataclasses import dataclass, field as dc_field
from typing import Any, Mapping, Sequence

from .labels import Label
from .lattice import BOTTOM, declassify as declassify_label, join
from .policy import ApprovalAuthority, Decision, Policy
from .taint import Tainted, detect_leak, join_values
from .tools import ToolError, Tools

__all__ = [
    "GuardConfig",
    "Plan",
    "PolicyViolation",
    "RunResult",
    "Runtime",
    "Step",
    "VARIANTS",
]


@dataclass(frozen=True)
class GuardConfig:
    """Which parts of the mechanism are enabled.

    ``use_labels=False`` turns the monitor into a baseline (keyword or
    allowlist).  The three ``track_*`` and ``*_provenance`` switches exist
    only so that the evaluation can remove one mechanism at a time; the
    shipped configuration is :data:`VARIANTS` ``["full"]``.
    """

    use_labels: bool = True
    track_substring: bool = True
    decode_taint: bool = True
    sink_provenance: bool = True
    keyword_filter: bool = False
    allowlist: bool = False
    allow_domains: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        data = {
            "use_labels": self.use_labels,
            "track_substring": self.track_substring,
            "decode_taint": self.decode_taint,
            "sink_provenance": self.sink_provenance,
            "keyword_filter": self.keyword_filter,
            "allowlist": self.allowlist,
        }
        if self.allowlist:
            data["allow_domains"] = list(self.allow_domains)
        return data


#: A static egress allowlist that covers the internal API but not the external
#: partner integration.  The omission is deliberate: it is the utility cost
#: that a real allowlist pays when a legitimate third party is not listed.
ALLOW_DOMAINS = ("api.internal.example",)

VARIANTS: dict[str, GuardConfig] = {
    "full": GuardConfig(allow_domains=ALLOW_DOMAINS),
    "no_substring_taint": GuardConfig(
        track_substring=False, allow_domains=ALLOW_DOMAINS
    ),
    "no_decode_taint": GuardConfig(
        decode_taint=False, allow_domains=ALLOW_DOMAINS
    ),
    "no_sink_provenance": GuardConfig(
        sink_provenance=False, allow_domains=ALLOW_DOMAINS
    ),
    "keyword_filter": GuardConfig(
        use_labels=False, keyword_filter=True, allow_domains=ALLOW_DOMAINS
    ),
    "allowlist_only": GuardConfig(
        use_labels=False, allowlist=True, allow_domains=ALLOW_DOMAINS
    ),
    "no_guard": GuardConfig(use_labels=False, allow_domains=ALLOW_DOMAINS),
}

KEYWORDS = (
    "canary-",
    "secret",
    "password",
    "credential",
    "api_key",
    "apikey",
)


@dataclass(frozen=True)
class Step:
    """One tool call in a plan."""

    id: str
    tool: str
    args: Mapping[str, Any] = dc_field(default_factory=dict)
    note: str = ""


@dataclass
class Plan:
    """A deterministic plan produced by a backend for one scenario."""

    scenario_id: str
    family: str
    steps: list[Step]
    canary: str | None = None
    meta: dict[str, Any] = dc_field(default_factory=dict)


class PolicyViolation(RuntimeError):
    """Raised when the monitor refuses a call."""

    def __init__(self, step_id: str, decision: Decision) -> None:
        super().__init__(
            "step %s denied by %s: %s"
            % (step_id, decision.rule_id, decision.explanation)
        )
        self.step_id = step_id
        self.decision = decision


@dataclass
class RunResult:
    scenario_id: str
    family: str
    variant: str
    completed: bool
    denied_at: str | None = None
    denial: dict[str, Any] | None = None
    audit: list[dict[str, Any]] = dc_field(default_factory=list)
    provenance: dict[str, Any] = dc_field(default_factory=dict)
    egress: dict[str, Any] = dc_field(default_factory=dict)
    steps_executed: int = 0
    canary: str | None = None

    def leaked(self, canary: str | None = None) -> bool:
        token = canary or self.canary
        if not token:
            return False
        payloads = self.payloads()
        return any(detect_leak(payload, token) for payload in payloads)

    def payloads(self) -> list[str]:
        records = self.egress.get("records", [])
        per_call = [
            "%s\n%s" % (record["url"], record["body"]) for record in records
        ]
        joined = "".join(record["body"] for record in records)
        return per_call + [joined]

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "family": self.family,
            "variant": self.variant,
            "completed": self.completed,
            "denied_at": self.denied_at,
            "denial": self.denial,
            "steps_executed": self.steps_executed,
            "audit": list(self.audit),
            "provenance": dict(self.provenance),
            "egress": dict(self.egress),
        }


class Runtime:
    """Executes a plan under a fixed policy and guard configuration."""

    def __init__(
        self,
        tools: Tools,
        policy: Policy | None = None,
        config: GuardConfig | None = None,
        authority: ApprovalAuthority | None = None,
        variant: str = "full",
    ) -> None:
        self.tools = tools
        self.policy = policy or Policy.default()
        self.config = config or VARIANTS["full"]
        self.authority = authority or ApprovalAuthority()
        self.variant = variant

    # ------------------------------------------------------------------
    # argument resolution
    # ------------------------------------------------------------------
    def _resolve(self, expr: Any, bindings: Mapping[str, Tainted],
                 refs: list[str]) -> Tainted:
        if isinstance(expr, Tainted):
            return expr
        if isinstance(expr, (str, int, float)) or expr is None:
            return Tainted.clean(expr)
        if not isinstance(expr, Mapping):
            raise TypeError("unsupported argument expression: %r" % (expr,))

        if "$ref" in expr:
            name = str(expr["$ref"])
            refs.append(name)
            if name not in bindings:
                raise KeyError("plan references unknown step %r" % name)
            return bindings[name]

        if "$const" in expr:
            return Tainted.clean(expr["$const"])

        if "$concat" in expr:
            parts = [self._resolve(item, bindings, refs)
                     for item in expr["$concat"]]
            # Import locally to keep the taint module the single source of
            # truth for concatenation semantics.
            from .taint import concat as concat_values

            return concat_values(*parts)

        if "$slice" in expr:
            base, start, end = _unpack(expr["$slice"], 3)
            value = self._resolve(base, bindings, refs)
            return value.slice(
                int(start),
                None if end is None else int(end),
                drop_taint=not self.config.track_substring,
            )

        if "$field" in expr:
            base, name = _unpack(expr["$field"], 2)
            value = self._resolve(base, bindings, refs)
            return value.field(
                str(name), drop_taint=not self.config.track_substring
            )

        if "$encode" in expr:
            base, kind = _unpack(expr["$encode"], 2)
            value = self._resolve(base, bindings, refs)
            return value.encode(
                str(kind), drop_taint=not self.config.decode_taint
            )

        if "$json" in expr:
            base, path = _unpack(expr["$json"], 2)
            value = self._resolve(base, bindings, refs)
            return value.json_path(
                str(path), drop_taint=not self.config.track_substring
            )

        raise ValueError("unknown argument expression keys: %s"
                         % sorted(expr))

    def _resolve_args(
        self, args: Mapping[str, Any], bindings: Mapping[str, Tainted]
    ) -> tuple[dict[str, Tainted], list[str]]:
        resolved: dict[str, Tainted] = {}
        refs: list[str] = []
        for name, expr in args.items():
            resolved[name] = self._resolve(expr, bindings, refs)
        return resolved, refs

    # ------------------------------------------------------------------
    # screening
    # ------------------------------------------------------------------
    @staticmethod
    def _host(args: Mapping[str, Tainted]) -> str:
        url = args.get("url")
        if url is None:
            return ""
        try:
            return urllib.parse.urlparse(url.text).hostname or ""
        except ValueError:
            return ""

    @staticmethod
    def _keyword_hit(payload: str) -> str | None:
        lowered = payload.lower()
        for keyword in KEYWORDS:
            if keyword in lowered:
                return keyword
        return None

    def _screen(
        self,
        step: Step,
        args: Mapping[str, Tainted],
        label: Label,
        cap: str,
    ) -> Decision:
        host = self._host(args)

        if not self.config.use_labels:
            if cap == "NET" and self.config.allowlist:
                if host not in self.config.allow_domains:
                    return Decision(
                        False,
                        "BASELINE-ALLOWLIST",
                        "destination %r is not on the allowlist" % host,
                        host,
                        cap,
                    )
            if cap == "NET" and self.config.keyword_filter:
                payload = "\n".join(value.text for value in args.values())
                hit = self._keyword_hit(payload)
                if hit:
                    return Decision(
                        False,
                        "BASELINE-KEYWORD",
                        "payload matched keyword %r" % hit,
                        host,
                        cap,
                    )
            return Decision(
                True,
                "BASELINE-PASS",
                "no label-aware check is enabled in this baseline",
                host,
                cap,
            )

        effective = label
        if cap == "NET":
            if self.config.sink_provenance:
                # Close over the whole request: every argument contributes
                # provenance, and so does anything already sent to this
                # channel.  A fragment cannot be laundered by a clean
                # neighbour.
                channel = self.channel_labels.get(host, BOTTOM)
                effective = join(channel, label)
            else:
                # Ablation: screen only the declared payload field and forget
                # earlier fragments.  This is the shape of a monitor that
                # inspects ``body`` and trusts the rest of the request.
                body = args.get("body")
                if body is not None:
                    effective = body.label
        return self.policy.check(effective, cap, host or step.tool)

    def _declassify(
        self, step: Step, args: Mapping[str, Tainted]
    ) -> tuple[Decision, Tainted | None]:
        value = args["value"]
        sink = args["sink"].text if "sink" in args else ""
        approval_id = step.args.get("approval")

        if not self.config.use_labels:
            return (
                Decision(True, "R-DECLASS-BYPASS",
                         "guard disabled; declassification is a no-op",
                         sink, "DECLASSIFY"),
                Tainted(value.value, declassify_label(value.label),
                        value.provenance),
            )

        decision = self.policy.check(value.label, "DECLASSIFY", sink)
        if decision.allowed:
            return decision, Tainted(
                value.value, declassify_label(value.label), value.provenance
            )
        if decision.rule_id != "R-DECLASSIFY-TOKEN":
            return decision, None
        if not approval_id:
            return (
                Decision(False, "R-DECLASS-NO-TOKEN",
                         "declassification attempted without an approval token",
                         sink, "DECLASSIFY"),
                None,
            )
        approval = self.authority.consume(str(approval_id), value.text, sink)
        if approval.allowed:
            return approval, Tainted(
                value.value, declassify_label(value.label), value.provenance
            )
        return approval, None

    # ------------------------------------------------------------------
    # execution
    # ------------------------------------------------------------------
    def run(self, plan: Plan) -> RunResult:
        self.channel_labels: dict[str, Label] = {}
        self.channel_provenance: dict[str, set[str]] = {}

        bindings: dict[str, Tainted] = {}
        audit: list[dict[str, Any]] = []
        nodes: list[dict[str, Any]] = []
        edges: list[dict[str, str]] = []
        seen_sources: set[str] = set()

        denied_at: str | None = None
        denial: dict[str, Any] | None = None
        executed = 0

        for seq, step in enumerate(plan.steps, start=1):
            args, refs = self._resolve_args(step.args, bindings)
            joined = join_values(list(args.values()))
            cap = self.tools.capability(step.tool)
            host = self._host(args)

            decision: Decision
            output: Tainted | None = None

            if step.tool == "declassify":
                decision, output = self._declassify(step, args)
            else:
                decision = self._screen(step, args, joined.label, cap)

            for source in joined.provenance:
                if source not in seen_sources:
                    seen_sources.add(source)
                    nodes.append(
                        {
                            "id": source,
                            "kind": "source",
                            "label": self.tools.sources.get(
                                source, joined.label
                            ).to_dict(),
                        }
                    )
            nodes.append(
                {
                    "id": step.id,
                    "kind": "step",
                    "tool": step.tool,
                    "note": step.note,
                    "label": joined.label.to_dict(),
                    "provenance": list(joined.provenance),
                    "sink": host,
                    "decision": decision.rule_id,
                    "allowed": decision.allowed,
                }
            )
            for ref in refs:
                edges.append({"from": ref, "to": step.id})

            audit.append(
                {
                    "seq": seq,
                    "step": step.id,
                    "tool": step.tool,
                    "sink": host,
                    "capability": cap,
                    "label": joined.label.to_dict(),
                    "rule_id": decision.rule_id,
                    "allowed": decision.allowed,
                    "explanation": decision.explanation,
                }
            )

            if not decision.allowed:
                denied_at = step.id
                denial = decision.to_dict()
                break

            if step.tool == "declassify":
                assert output is not None
                bindings[step.id] = output
                nodes[-1]["label"] = output.label.to_dict()
                nodes[-1]["provenance"] = list(output.provenance)
                audit[-1]["output_label"] = output.label.to_dict()
            else:
                try:
                    output = self.tools.call(step.tool, args, step.id)
                except ToolError as exc:
                    raise ToolError("step %s: %s" % (step.id, exc)) from exc
                bindings[step.id] = output
                nodes[-1]["label"] = output.label.to_dict()
                nodes[-1]["provenance"] = list(output.provenance)
                if cap == "NET" and self.config.sink_provenance:
                    previous = self.channel_labels.get(host, BOTTOM)
                    self.channel_labels[host] = join(previous, joined.label)
                    self.channel_provenance.setdefault(host, set()).update(
                        joined.provenance
                    )
                audit[-1]["output_label"] = output.label.to_dict()

            # Sources are registered from the outputs as well as from the
            # inputs: a value read but never consumed downstream still needs
            # a node, otherwise the exported graph is missing the read that
            # produced the untrusted page in the first place.
            for source in output.provenance:
                if source not in seen_sources:
                    seen_sources.add(source)
                    nodes.append(
                        {
                            "id": source,
                            "kind": "source",
                            "label": self.tools.sources.get(
                                source, output.label
                            ).to_dict(),
                        }
                    )
            executed += 1

        graph = {
            "scenario_id": plan.scenario_id,
            "family": plan.family,
            "variant": self.variant,
            "nodes": nodes,
            "edges": edges,
            "channel_labels": {
                host: label.to_dict()
                for host, label in sorted(self.channel_labels.items())
            },
        }

        return RunResult(
            scenario_id=plan.scenario_id,
            family=plan.family,
            variant=self.variant,
            completed=denied_at is None,
            denied_at=denied_at,
            denial=denial,
            audit=audit,
            provenance=graph,
            egress=self.tools.egress.to_dict(),
            steps_executed=executed,
            canary=plan.canary,
        )


def _unpack(value: Any, arity: int) -> tuple[Any, ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise TypeError("expression expects a list of %d items" % arity)
    if len(value) != arity:
        raise TypeError("expression expects %d items, got %d"
                        % (arity, len(value)))
    return tuple(value)


def render_tree(result: RunResult) -> str:
    """Render the provenance tree of a run as ASCII, for ``agent-gate audit``."""
    nodes = {node["id"]: node for node in result.provenance.get("nodes", [])}
    children: dict[str, list[str]] = {}
    for edge in result.provenance.get("edges", []):
        children.setdefault(edge["from"], []).append(edge["to"])

    roots = [node_id for node_id in nodes if node_id not in
             {edge["to"] for edge in result.provenance.get("edges", [])}]
    lines: list[str] = []

    def walk(node_id: str, depth: int) -> None:
        node = nodes.get(node_id)
        if node is None:
            return
        indent = "  " * depth
        if node["kind"] == "source":
            lines.append("%s[src] %s  %s" % (
                indent, node_id, _label_text(node["label"])))
        else:
            verdict = "allow" if node.get("allowed") else "DENY"
            lines.append("%s[%s] %-10s %-5s %s" % (
                indent, node["id"], node["tool"], verdict,
                _label_text(node["label"])))
            if node.get("sink"):
                lines.append("%s      sink=%s rule=%s" % (
                    indent, node["sink"], node.get("decision")))
        for child in children.get(node_id, []):
            walk(child, depth + 1)

    for root in sorted(roots):
        walk(root, 0)

    header = "provenance tree for %s (%s, variant=%s)" % (
        result.scenario_id, result.family, result.variant)
    footer = "result: %s" % (
        "completed" if result.completed
        else "denied at %s by %s" % (
            result.denied_at, (result.denial or {}).get("rule_id")))
    return "\n".join([header, "-" * len(header), *lines, "-" * len(header),
                      footer])


def _label_text(label: dict[str, Any]) -> str:
    caps = ",".join(label.get("capabilities", [])) or "-"
    return "I=%s C=%s caps=%s" % (
        label.get("integrity"), label.get("confidentiality"), caps)
