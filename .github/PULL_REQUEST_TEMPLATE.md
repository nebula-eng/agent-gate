## What this changes

<!-- One paragraph. If it moves a reported number, give the before and after. -->

## Kind

- [ ] Defect fix
- [ ] New protocol, parser or detector
- [ ] New measurement or experiment
- [ ] Documentation
- [ ] Refactor with no behaviour change

## Design rules

- [ ] The monitor decides before the tool executes. A denial raises; no bytes reach the sink.
- [ ] `join` is the least upper bound of the lattice, so no operator returns something less restrictive than its inputs. A new operator needs its propagation rule and a lattice test.
- [ ] The corpus is generated deterministically (seed 1337) and digested over canonical JSON, so it survives a checkout. `scripts/gen_scenarios.py --check` fails on drift.
- [ ] Deterministic results go to `results/results.json`, timing to `results/timing.json`.

- [ ] `PYTHONPATH=src python -m unittest discover -s tests -v` passes
- [ ] Reported numbers regenerated from `results/results.json`, not hand-edited
- [ ] Documentation updated where behaviour is user-visible

## Evidence

<!-- For a new detector or measurement: the input that triggers it, and one that must
not. False positives matter as much as detections. -->

## Notes for review

<!-- Ordering assumptions, overlap policy, performance trade-offs. -->
