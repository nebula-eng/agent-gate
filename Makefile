PYTHON ?= python
export PYTHONPATH := src

.PHONY: all test eval gen figures demo audit check clean

all: test eval figures

## Run the unit test suite (unittest, no third-party runner required).
test:
	$(PYTHON) -m unittest discover -s tests -v

## Regenerate data/scenarios/*.json from seed 1337.
gen:
	$(PYTHON) scripts/gen_scenarios.py

## Verify the generated corpus and the committed results.
check:
	$(PYTHON) scripts/gen_scenarios.py --check
	$(PY) scripts/check_repro.py

## Run the corpus, write results/results.json and results/timing.json.
eval:
	$(PYTHON) -m agent_gate.cli eval

## Render the three figures from results/results.json.
figures:
	$(PYTHON) scripts/make_figures.py

## One scenario, with and without the monitor.
demo:
	$(PYTHON) -m agent_gate.cli demo --scenario att-tool_confusion-00 --audit

## Provenance tree for one scenario.
audit:
	$(PYTHON) -m agent_gate.cli audit --scenario att-split_exfil-00

clean:
	$(PYTHON) -c "import pathlib, shutil; [shutil.rmtree(p, ignore_errors=True) for p in pathlib.Path('.').rglob('__pycache__')]"
	$(PYTHON) -c "import shutil; shutil.rmtree('results/.runtime', ignore_errors=True)"
