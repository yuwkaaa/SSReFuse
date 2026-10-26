# SSReFuse. Everything runs through the project venv so a system Python upgrade
# cannot change a measurement.
PY := .venv/bin/python
VENV := .venv

.PHONY: help venv validate selftest probe scan report judge judge-opencode all test clean

help:
	@echo "make venv      - create .venv and install dependencies"
	@echo "make validate  - check the corpus against its source markers"
	@echo "make selftest  - build the sandbox and prove it is hermetic"
	@echo "make probe     - fire the payload catalog at every lab variant"
	@echo "make scan      - run the static detectors with their positive control"
	@echo "make report    - score everything measured so far into results/report.md"
	@echo "make judge     - run the LLM judge (needs DEEPSEEK_API_KEY in .env)"
	@echo "make judge-opencode - the same tier through a running opencode server, no key"
	@echo "make all       - validate, probe, scan, report"
	@echo "make test      - run the test suite"

$(VENV)/bin/python:
	python3.13 -m venv $(VENV) || python3 -m venv $(VENV)
	$(VENV)/bin/pip install -q --upgrade pip
	$(VENV)/bin/pip install -q -e ".[static,dev]"

venv: $(VENV)/bin/python

validate: venv
	PYTHONPATH=. $(PY) -m ssrefuse.cli validate

selftest: venv
	PYTHONPATH=. $(PY) -m ssrefuse.cli selftest

probe: venv
	PYTHONPATH=. $(PY) -m ssrefuse.cli probe

scan: venv
	PYTHONPATH=. $(PY) -m ssrefuse.cli scan

report: venv
	PYTHONPATH=. $(PY) -m ssrefuse.cli report

# The judge needs a key in .env or in the environment. The ablation holds the
# model fixed and moves the thinking budget, which is why both runs name the
# same model; the cache is keyed on the effort too, so neither serves the
# other's answers and a repeat of either is free.
judge: venv
	PYTHONPATH=. $(PY) -m ssrefuse.cli judge --effort off  --rounds 2
	PYTHONPATH=. $(PY) -m ssrefuse.cli judge --effort high --rounds 2
	PYTHONPATH=. $(PY) -m ssrefuse.cli report

# The same tier through a locally running opencode server, which holds the
# account's credential, so there is no key here and no per-call charge beyond
# the subscription. Two things differ from the target above and both are
# deliberate. The arms are `low` and `high` rather than `off` and `high`,
# because this transport spells the thinking budget as a declared model
# variant and declares none that disables thinking -- `off` would have to be
# faked as "the model's default" and would then be a column labelled with a
# budget it did not run at. And the cost table prints n/a for these rows: the
# endpoint returns the answer and no accounting, which is a different fact
# from a run that spent nothing. Needs `opencode service start`.
OC_MODEL ?= opencode-go/deepseek-v4.1-flash
judge-opencode: venv
	PYTHONPATH=. $(PY) -m ssrefuse.cli judge --provider opencode --model $(OC_MODEL) --effort low  --rounds 2
	PYTHONPATH=. $(PY) -m ssrefuse.cli judge --provider opencode --model $(OC_MODEL) --effort high --rounds 2
	PYTHONPATH=. $(PY) -m ssrefuse.cli report

all: venv
	PYTHONPATH=. $(PY) -m ssrefuse.cli all

test: venv
	PYTHONPATH=. $(PY) -m pytest tests -q

clean:
	rm -rf results/probe results/selftest results/*.md results/static-runs.json
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
