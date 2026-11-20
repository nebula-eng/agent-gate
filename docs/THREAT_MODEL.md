# Threat model

## 1. Summary

agent-gate defends one asset against one adversary using one mechanism:

* Asset: the confidentiality of values the agent can read (API keys,
  customer records, private documents) and the integrity of the actions the
  agent takes on the operator's behalf.
* Adversary: anyone who can write to a channel the agent reads through --
  a web page, a file dropped in a shared folder, an email body, a third-party
  API response.
* Mechanism: a reference monitor that labels values, propagates labels
  through every derivation the planner can express, and refuses tool calls
  whose label violates a declarative policy.

Out of scope by construction: making the model behave, detecting "prompt
injection" as a text phenomenon, and protecting data the agent never reads.

## 2. Attacker model

The attacker can:

* fully control the bytes of any tool output the agent consumes (page body,
  file content, email body, API response);
* choose those bytes adaptively for a known agent, including instructions
  that name the tools, paths, and endpoints to use;
* encode the payload in base64, hex, percent-escapes, or zero-width
  characters, and split it across requests;
* exploit any tool the agent has, including tools whose purpose is unrelated
  to data movement (a URL parameter, a filename, a query string);
* replay, reuse, or forge approval-token identifiers inside a plan.

The attacker cannot:

* read or modify the monitor's code, policy, or approval authority;
* observe the label of a value or the decision rule that will fire (no oracle);
* write to the audit log;
* change which sources the integration labels `TRUSTED`.

The attacker is *not* assumed to be a specific model. The corpus is written
against the tool layer, not against a prompt, which is why it survives a
change of planner.

## 3. Trusted computing base

Everything below is assumed correct:

1. the label lattice and the propagation operators (`labels`, `lattice`,
   `taint`);
2. the policy compiler and the rule set (`policy`);
3. the runtime's resolution and screening order (`runtime`);
4. the tool declarations mapping a tool to a capability (`tools.TOOL_CAPS`);
5. the approval authority and the process that mints tokens;
6. the source-labelling declarations in the integration (which file is
   `SECRET`, which page is `UNTRUSTED`);
7. the Python interpreter and the host OS.

Items 1-4 are small enough to review in one sitting; item 5 is an
organisational control; item 6 is the weakest link and is discussed below.

## 4. Assets and security goals

| asset | goal | mechanism |
|---|---|---|
| secret values (credentials, PII) | no egress without an approved, bound, one-shot token | `R-NET-SECRET` + approvals |
| operator intent | attacker-controlled text cannot steer a write | `R-NET-UNTRUSTED` |
| action integrity | a value derived from untrusted text cannot be declassified | declassify preserves integrity |
| auditability | every refusal is explainable after the fact | decision objects with rule ids |
| utility | benign flows keep working | `R-NET-CLEAN`, scoped approvals |

## 5. Assumptions

| id | assumption | if violated |
|---|---|---|
| A1 | every value entering the runtime is created by a labelled tool or a literal | unlabelled data flows unchecked |
| A2 | every derivation the planner can express is one of the operators in `DESIGN.md` 3.2 | a derivation escapes taint |
| A3 | source labels are declared correctly by the integration | a secret read as `PUBLIC` is exportable |
| A4 | the policy is written by the operator and not influenced by tool output | the attacker writes their own rules |
| A5 | approvals are minted by a process outside the agent's control | the agent approves itself |
| A6 | the tool capability table matches what the tool can actually do | a `NET` capability hidden behind an `FS_WRITE` tool |
| A7 | the sandbox is the only filesystem the agent can reach | data leaves through an unmonitored path |
| A8 | the egress recorder observes every outbound byte | leaks happen off the record |

A6 is the assumption most likely to break in a real deployment: a plugin that
"only writes a file" but uploads it is an unlabelled egress channel.

## 6. Why prompt filtering is insufficient

The measured baselines make the argument concrete rather than rhetorical. All
rows are from `results/results.json`, same 60 plans:

| defence | ASR | what it misses |
|---|---|---|
| no guard | 1.0000 | everything |
| keyword filter | 0.2333 | base64/hex/zero-width bodies (0.8000), split fragments (0.6000) |
| static egress allowlist | 0.5000 | exfiltration through the allowlisted endpoint (1.0000 on three families) |
| full system | 0.0000 | -- |

A prompt-level defence has the same shape as the keyword filter: it inspects
the *content* of a single step and decides. Content inspection is defeated by
any encoding the monitor does not enumerate, and by any split the monitor does
not reassemble. The mechanism is different in kind: it does not ask "does this
string look like a secret", it asks "where did these bytes come from, and
where are they going". The answer is a property of the plan, not of the
phrasing, so paraphrase and encoding of the *transport* do not change it.

That said, content inspection is still useful as defence in depth; the point
is that it cannot be the primary control.

## 7. Soundness argument sketch

Definitions. A *trace* is a sequence of steps. A value `v` has label
`L(v)`. A step `s` with capability `c` and resolved arguments `a_1..a_k` is
*screened* on `J = join(L(a_1), ..., L(a_k), channel(c))`.

Invariant (I). For every value `v` produced in a trace, every byte of `v`
that originated from source `x` satisfies `L(x) <= L(v)`.

Lemma 1 (base). Sources are created with their declared label; literals
are created at bottom. `L(x) <= L(x)` and `BOTTOM <= L(v)` hold trivially.

Lemma 2 (step). Every operator returns `join` of its inputs (or, for
`declassify`, a label that only lowers confidentiality). By induction on the
derivation, `L(v)` dominates every input label, hence every source label
contributing a byte.

Theorem (noninterference, conditional). Assume (I), a policy in which every
rule that denies a label `J` is sound with respect to the intended flow
restriction, and that no declassification with a valid token occurred. Then no
byte of a value labelled `SECRET` or `UNTRUSTED` reaches a `NET` sink.

*Proof.* Let `s` be the first `NET` step whose payload contains such a byte.
By (I) the byte's source `x` satisfies `L(x) <= J`. Since the byte is secret
or untrusted, `L(x)` is `SECRET` or `UNTRUSTED`, so `J` is too (join is
monotone). If `J.confidentiality = SECRET`, `R-NET-SECRET` matches; if
`J.integrity = UNTRUSTED`, `R-NET-UNTRUSTED` matches. In both cases the
decision is deny and the step does not execute, contradicting that `s` sent
the byte. The only escape is the declassification path, excluded by
assumption. QED.

The theorem is conditional, and the conditions are exactly the assumptions in
section 5. It is not a claim about the model.

## 8. Where the argument breaks

B1. The planner is inside the trusted base. The theorem covers bytes that
*flow through the runtime*. A planner that has already read a secret into its
own context can emit `{"$const": "CANARY-..."}` in a later step; that literal
is bottom-labelled and no derivation edge exists. The monitor cannot
distinguish "the model wrote this string" from "the operator wrote this
string". This is not a bug to be fixed at the tool boundary: any monitor that
cannot see the model's internals has this hole. Mitigations are architectural
(never put secrets in the planner's context; split readers and writers into
different principals), not algorithmic.

B2. Semantic paraphrase. A model that restates a secret in its own words
("the key starts with CANARY and ends with 9abcdef") produces a new string
with no provenance. The canary metric would not fire, and the label would be
bottom. This is the same hole as B1 seen from the content side. The corpus
does not measure it because a scripted planner cannot express it; the honest
statement is that agent-gate is sound for flows it can see.

B3. Covert channels. Timing, message size, request ordering, and the
choice of destination are unlabelled. A policy that permits a public value to
egress also permits a low-bandwidth signal encoded in *when* it egresses. The
channel closure in section 5.3 does not address this.

B4. Mislabeled sources. If the integration declares an attacker-writable
file as `TRUSTED`, `R-NET-UNTRUSTED` never fires. A3 is doing real work here,
and it is a policy decision made outside this code. The corpus assumes the
declarations are correct; a production deployment needs review of the source
inventory, not more runtime rules.

B5. Approved insiders. A valid token is a deliberate hole. The mechanism
enforces that the token names *this* value and *this* sink and is used once; it
does not enforce that the approval was a good idea. The `replay`, `wrong_sink`,
`hash_mismatch`, `unknown_token`, and `no_token` scenarios in the corpus are
attacks on the *binding*, not on the judgement.

B6. Unlabelled egress. A tool that writes a file which a separate process
uploads is an egress channel the recorder never sees. A6 and A7 are load
bearing. The capability table is the trust boundary; a plugin that lies about
its capability defeats every rule.

B7. Declassification breadth. Declassifying a *summary* declassifies
whatever the summariser chose to keep. The benign `public_post` flow releases
a projection built from named fields precisely to keep this narrow; a
summariser asked to "release the gist" would be a much wider hole.

## 9. Corpus families and what each one probes

| family | attacker move | mechanism under test | fails when |
|---|---|---|---|
| `direct_inject` | page instructs the agent to POST a file | untrusted-to-egress rule | integrity is not tracked |
| `indirect_file` | handbook note carries the instruction | same, different source channel | file content is trusted by default |
| `encoded_exfil` | body is base64/hex/zwsp/percent | taint through encode/decode | encoding is treated as sanitising |
| `split_exfil` | canary split across two requests | substring taint + channel closure | taint lost at `slice`, or no per-sink state |
| `tool_confusion` | canary in the URL path, body clean | whole-request screening | only the body is inspected |
| `legit_declassify_abuse` | reuse/forge/misdirect a token | token binding and one-shot use | approvals are advisory |

## 10. Residual risk statement

With the full configuration, on this corpus, the monitor blocks 60/60 attacks
with 0/25 false positives and 25/25 benign tasks completed. That result is
conditional on A1-A8 and does not survive B1, B2, B3, or B6. A deployment that
places secrets in the planner's context, or that installs a tool whose real
capability is broader than its declaration, has a hole that this evaluation
cannot see and does not claim to close.
