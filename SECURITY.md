# Security policy

## Reporting a vulnerability

Report privately through GitHub's [security advisory
form](https://github.com/nebula-eng/agent-gate/security/advisories/new). The
report is visible only to the maintainer. There is no mailing list, so nothing sent
to an address at this project's name reaches anyone.

Include the command you ran, the input that triggers the problem, and the Python
version. You will get an acknowledgement within 72 hours.

## What counts here

This project labels every value with an information-flow label, propagates it through every derivation, and refuses a tool call before it runs when the join of its arguments may not reach that sink. That shapes what a vulnerability is:

- Attacks are executed by a deterministic scripted planner, not a live model. The claim is about the reference monitor, not about any model's willingness to follow instructions.
- Semantic paraphrase produced inside the model leaves no derivation edge to follow. Covert channels (timing, size, ordering, destination choice) are not labelled.
- Source labelling is a policy decision made outside this code. A source declared `TRUSTED` when it is attacker-controlled voids the soundness argument.

A wrong verdict with no crash is in scope. In a measurement artifact a silently wrong
number is worse than an exception, because nothing prompts a reader to check it.

## Out of scope

- Anything that requires modifying the repository before running it.
- Differences caused by the host, where the README already states that a number is
  machine-dependent.
- The limits listed under Limitations in the README. They are known and written
  down; a report that restates one is not a finding.

## Data handling

`http_get` reads a canned page registry and `http_post` writes to an in-process recorder. The optional OpenAI-compatible adapter is not used by the evaluation.
