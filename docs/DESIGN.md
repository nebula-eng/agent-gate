# Design

This document describes the mechanism as implemented. Line references point
at the module that owns each rule; the evaluation and its caveats live in
`EVALUATION.md` and `THREAT_MODEL.md`.

## 1. Scope

agent-gate is a reference monitor for one specific transition: a value that
entered the agent from a low-integrity or high-confidentiality source is about
to be passed to a tool that can move it somewhere else. The monitor sits
between the planner and the tool layer. It does not parse prompts, does not
score text for "injection-likeness", and does not ask a model for an opinion.

Three properties are treated as requirements rather than goals:

* Fail closed on the check. A denied call never reaches the tool. There is
  no "log and continue" mode; ablation variants are explicit configuration,
  not fallbacks.
* Total propagation. Every operator exposed to the planner either joins
  labels or is absent from the operator set. There is no operator that returns
  an unlabelled value except the explicit, audited declassification path.
* Auditable decisions. Every check returns `(allowed, rule_id,
  explanation, sink, capability)` and is appended to the run's audit log.

## 2. Label lattice

### 2.1 Domain

```
Label = (integrity, confidentiality, capabilities)
integrity        : TRUSTED | UNTRUSTED
confidentiality  : PUBLIC  | SECRET
capabilities     : P({NET, NET_IN, FS_READ, FS_WRITE, LLM, DECLASSIFY, NONE})
```

`capabilities` records which sink classes a value has already been exposed to
or is allowed to touch. In practice it is used for audit and for future
per-sink policy; the shipped rule set decides on integrity, confidentiality,
and the *sink's* capability.

`NET` is egress only. `http_get` declares `NET_IN`, deliberately: treating a
fetch as an egress sink would block reading rather than exfiltration and would
let the mechanism look correct for the wrong reason. Reads are sources.

### 2.2 Order

`a <= b` iff `a` is at least as restrictive as `b` on every component:

```
integrity:        TRUSTED <= UNTRUSTED
confidentiality:  PUBLIC  <= SECRET
capabilities:     a.capabilities subset-of b.capabilities
```

The order is a product order: it is a partial order, not a chain. A trusted
secret and an untrusted public value are incomparable, which is why the
policy needs a rule per dimension instead of one "badness" score.

Bottom is `(TRUSTED, PUBLIC, {})`, the label of a freshly computed constant.
Top is `(UNTRUSTED, SECRET, all capabilities)`.

### 2.3 Join

`join` is componentwise maximum / set union. It is the operation used
everywhere a value is built from others, because the result must dominate
every input.

| join | T/P | T/S | U/P | U/S |
|---|---|---|---|---|
| T/P | T/P | T/S | U/P | U/S |
| T/S | T/S | T/S | U/S | U/S |
| U/P | U/P | U/S | U/P | U/S |
| U/S | U/S | U/S | U/S | U/S |

`meet` is componentwise minimum / intersection and is used only in the
lattice-law tests and in `declassify`-adjacent reasoning; it is not part of
any decision path.

### 2.4 Order table

| a <= b | T/P | T/S | U/P | U/S |
|---|---|---|---|---|
| T/P | yes | yes | yes | yes |
| T/S | - | yes | - | yes |
| U/P | - | - | yes | yes |
| U/S | - | - | - | yes |

### 2.5 Declassification

```
declassify(T/S) = T/P        confidentiality drops to PUBLIC
declassify(U/S) = U/P        integrity is preserved
```

Integrity is never raised. An approval lets a value leave the organisation; it
does not make attacker-controlled bytes trustworthy, so an approved dump of an
untrusted page is still refused at `NET` by `R-NET-UNTRUSTED`. This is the
single most important asymmetry in the design: declassification is a
confidentiality operation, not an integrity operation.

### 2.6 Laws

The product construction gives idempotence, commutativity, associativity, and
both absorption laws for free. `tests/test_lattice.py` re-derives them over a
sampled subset of the label space (64 labels, 8x8x8 triples for associativity)
rather than trusting the construction, because an ordering bug here is silent:
every decision would still return a verdict.

## 3. Taint model

### 3.1 Structure

```python
@dataclass(frozen=True)
class Tainted:
    value: Any                              # str, dict, list, ...
    label: Label
    provenance: tuple[str, ...]             # source ids, e.g. "src:file:secrets/..."
```

Provenance is a set of origin identifiers, not a tree. The tree is
reconstructed by the runtime from plan references (`src/agent_gate/runtime.py`,
`provenance` export), which keeps values small and the graph explicit.

### 3.2 Propagation rules

| operation | label of result | provenance |
|---|---|---|
| assignment / literal | unchanged | unchanged |
| `concat(*parts)` | join of all parts | union |
| `fmt(template, *args)` | join of args | union |
| `slice(start, end)` | unchanged | unchanged |
| `field("NAME")` (line extraction) | unchanged | unchanged |
| `json_path("a.b")` | unchanged | unchanged |
| `encode("base64"/"hex"/"zwsp"/"url")` | unchanged | unchanged |
| `decode_all()` | unchanged | unchanged |
| tool `summarize(text)` | label of `text` | union |
| tool `read_file(path)` | label stored at write time | `src:file:<path>` |
| tool `http_get(url)` | page label, normally `UNTRUSTED` | `src:http_get:<url>` |
| `declassify` | confidentiality set to `PUBLIC` | unchanged |
| write then read | label stored on disk and restored | new source id |

Sliding the label through a substring is the property that makes split
exfiltration detectable. A monitor that taints at value granularity loses the
label at `substr`; `no_substring_taint` models exactly that failure and its
cost (ASR 0.3333).

### 3.3 Encodings

`decode_candidates(text)` recognises four families:

* base64: `[A-Za-z0-9+/]{16,}={0,2}`, decoded with validation and a
  printable-ratio filter to avoid decoding random identifiers;
* hex: `[0-9a-fA-F]{16,}` with even length;
* percent: runs of `%XX`, decoded with `unquote`;
* zero-width: bit strings over U+200B/U+200C, plus plain text with invisible
  code points interleaved (stripped back to the original).

Decoded payloads inherit the source label. This matters in both directions:
encoding a secret does not launder it (`encode` preserves the label), and
decoding an attacker payload does not clean it (`decode` preserves the label).

### 3.4 Canary and the leak predicate

Each scenario owns a unique canary `CANARY-<16 hex>`. A sink is recorded as
leaked only if the exact canary bytes appear in the egress stream under one of
its known transformations: plain, base64 (padded and unpadded), hex (either
case), zero-width interleaved, zero-width bit-encoded, percent-encoded, or
after stripping/normalising invisible characters and decoding candidates two
levels deep.

This is deliberately stricter and narrower than "the output looks like the
secret": no similarity score, no token overlap, no threshold. The measurement
cannot drift with the model's phrasing.

`EgressRecorder.bodies()` concatenates every body in call order, and the leak
predicate runs over both per-call payloads (`url + body`) and the
concatenation. That is what makes `split_exfil` measurable: neither fragment
contains the canary, the concatenation does.

## 4. Policy

### 4.1 Grammar

```
policy    := { "version": int, "default_effect": "allow" | "deny",
               "rules": [ rule+ ] }
rule      := { "id": str, "when": predicate, "effect": "allow" | "deny",
               "explanation": str }
predicate := { "sink_cap"?: cap,
               "integrity"?: "TRUSTED" | "UNTRUSTED",
               "confidentiality"?: "PUBLIC" | "SECRET",
               "capability"?: cap,
               "sink_name"?: str }
```

Evaluation is ordered, first match wins, and the default applies only when no
rule matches. Rules are data: the checker is 40 lines and has no knowledge of
any specific deployment.

### 4.2 Shipped rule set

| rule id | predicate | effect | rationale |
|---|---|---|---|
| `R-NET-UNTRUSTED` | `sink_cap=NET, integrity=UNTRUSTED` | deny | injection becomes exfiltration |
| `R-NET-SECRET` | `sink_cap=NET, confidentiality=SECRET` | deny | secret egress without approval |
| `R-NET-CLEAN` | `sink_cap=NET, TRUSTED, PUBLIC` | allow | the explicitly safe case |
| `R-DECLASSIFY-UNTRUSTED` | `sink_cap=DECLASSIFY, integrity=UNTRUSTED` | deny | approval does not raise integrity |
| `R-DECLASSIFY-TOKEN` | `sink_cap=DECLASSIFY` | deny | declassification requires a token |
| `R-DEFAULT-ALLOW` | (empty) | allow | uncovered flows are not denied by accident |

The order matters: `(UNTRUSTED, SECRET)` at `NET` matches
`R-NET-UNTRUSTED` first, so the audit log names the integrity problem rather
than the confidentiality one.

### 4.3 Approvals

```
issue(id, value_text, sink, nonce) -> Approval{ id, sha256(value), sink, nonce }
consume(id, value_text, sink)      -> Decision
```

`consume` checks, in order: token exists; not already consumed; sink matches;
value digest matches. Each failure has its own rule id (`R-DECLASS-UNKNOWN-
TOKEN`, `R-DECLASS-REPLAY`, `R-DECLASS-SINK-MISMATCH`,
`R-DECLASS-VALUE-MISMATCH`), and a success returns `R-DECLASS-APPROVED`.
Consumption is destructive, so a token is a capability with exactly one use.

The authority stores digests, never values. A compromised audit log therefore
does not leak the approved content.

### 4.4 Decision object

```json
{"allowed": false, "rule_id": "R-NET-SECRET",
 "explanation": "secret value may not reach a network sink without ...",
 "sink": "collector.evil.example", "sink_cap": "NET"}
```

Every decision in a run is appended to `RunResult.audit` with the sequence
number, step id, tool, resolved label, and rule id. `agent-gate audit`
renders the same data as a tree.

## 5. Runtime

### 5.1 Plan grammar

```
plan  := [ step+ ]
step  := { "id": "s1", "tool": "http_post", "args": { ... } }
expr  := literal | {"$ref": step_id} | {"$const": value}
       | {"$concat": [expr, ...]}      | {"$slice": [expr, start, end]}
       | {"$field": [expr, "NAME"]}    | {"$json": [expr, "a.b"]}
       | {"$encode": [expr, "base64"|"hex"|"zwsp"|"url"|"none"]}
```

Plans are data. The scripted backend emits them from the scenario spec; a real
model would emit the same shape.

### 5.2 Sequence

```
 planner            runtime                 policy            tools / audit
    |                  |                       |                  |
    |--- plan -------->|                       |                  |
    |                  | resolve $ref/$concat  |                  |
    |                  | join label + prov     |                  |
    |                  |-- check(label, cap) ->|                  |
    |                  |<-- (allow, rule) -----|                  |
    |                  |  deny: record + raise PolicyViolation ----->|
    |                  |  allow: call tool ------------------------>|
    |                  |<---------------------------- Tainted out ---|
    |                  | update channel label  |                  |
    |                  | append audit entry ---------------------->|
    |<-- RunResult ----|                       |                  |
```

### 5.3 Channel closure

For a `NET` sink, the label used for the decision is

```
effective = join(channel_label[host], label_of_all_arguments)
```

`channel_label[host]` is the join of every value already sent to that host in
this run. The check therefore covers three things at once: the current
payload, every other field of the current request (URL, headers, body), and
anything sent earlier to the same destination. A fragment cannot be laundered
by a clean neighbour or by being sent in a second request.

The `no_sink_provenance` ablation removes both halves of this: it screens only
the declared body and forgets earlier fragments, which is the shape of a
monitor that "inspects the payload" and trusts the rest of the request.

### 5.4 Provenance graph

Each run exports:

```json
{"scenario_id": "...", "family": "...", "variant": "full",
 "nodes": [{"id": "s2", "kind": "step", "tool": "read_file",
            "label": {...}, "sink": "", "decision": "R-DEFAULT-ALLOW"}],
 "edges": [{"from": "s2", "to": "s4"}],
 "channel_labels": {"api.internal.example": {...}}}
```

Source nodes are created from provenance ids and carry the label the tool
recorded for that source. Step nodes carry the label of the resolved
arguments, replaced by the output label once the call succeeds, so the tree
shows what actually flowed.

### 5.5 Failure semantics

A denial raises `PolicyViolation` at the step, records the decision, and stops
the run. Partial executions are reported honestly: `steps_executed` is the
number of calls that actually reached the tool layer, and `egress.records` is
empty for a run denied at its only egress point.

## 6. Ablations

Ablations are implemented as explicit `drop_taint=True` calls at the runtime
boundary, not as flags threaded through every helper. The unsound choice lives
in one file and is greppable:

```
track_substring=False  ->  slice/field/json return a clean value
decode_taint=False     ->  encode/decode return a clean value
sink_provenance=False  ->  screen only args["body"], no channel closure
keyword_filter=True    ->  no labels; scan body+url for keywords
allowlist=True         ->  no labels; destination allowlist
```

## 7. Complexity

Let `S` be the number of steps, `A` the number of arguments per step, `n` the
size of a value, `L` the number of provenance entries, and `m` the size of a
payload scanned by the leak predicate.

* Argument resolution: `O(A * n)` per step for concatenation and slicing;
  encoding adds `O(n)`.
* Label join: `O(A * |caps|)` per step; the lattice has 2 x 2 x 2^7 points, so
  this is a constant in practice.
* Policy: `O(R)` rule matches, `R` <= 6 in the shipped policy.
* Leak predicate: `O(m)` for the direct forms, plus regex scans and up to two
  rounds of decoding, `O(m log m)` in the worst case and `O(m)` for the
  payloads in this corpus.
* Space: provenance is `O(L)` per value, bounded by the number of sources in a
  plan; the audit log is `O(S)`.

The evaluation's 595 runs finish in about 9 seconds on the reference machine,
which is dominated by sandbox file I/O rather than by checking.

## 8. Invariants the tests pin down

1. Lattice laws hold on the sampled label space.
2. `join` is an upper bound and `meet` a lower bound of both operands.
3. Every propagation operator in section 3.2 keeps or raises the label.
4. `drop_taint=True` is the only way to lower a label, and it is never used by
   the shipped configuration.
5. A canary is detected in every encoding family, including double-encoded
   base64 and split fragments.
6. A consumed approval token is refused on replay, on a different sink, and on
   a different value.
7. All 60 attacks are blocked and all 25 benign tasks complete with the full
   configuration.
