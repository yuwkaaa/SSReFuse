# SSReFuse. Everything runs through the project venv so a system Python upgrade
# cannot change a measurement.
PY := .venv/bin/python
VENV := .venv

.PHONY: help venv preflight validate selftest probe scan report judge judge-opencode bench all test clean

help:
	@echo "make venv      - create .venv and install dependencies"
	@echo "make preflight - check this machine can run a bench, before running one"
	@echo "make validate  - check the corpus against its source markers"
	@echo "make selftest  - build the sandbox and prove it is hermetic"
	@echo "make probe     - fire the payload catalog at every lab variant"
	@echo "make scan      - run the static detectors with their positive control"
	@echo "make report    - score everything measured so far into results/report.md"
	@echo "make judge     - run the LLM judge (needs DEEPSEEK_API_KEY in .env)"
	@echo "make judge-opencode - the same tier through a running opencode server, no key"
	@echo "make all       - validate, probe, scan, report"
	@echo "make bench     - preflight, then the full measurement including both judge arms"
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

preflight: venv
	PYTHONPATH=. $(PY) -m ssrefuse.cli preflight --provider $(PROVIDER) --effort off

all: venv
	PYTHONPATH=. $(PY) -m ssrefuse.cli all

# One measurement, start to finish, for a machine that is not this one.
# preflight runs first and exits non-zero on anything that would stop the run
# part way, because a results directory from a half-finished bench looks like
# a result. Then the corpus is validated, every payload is fired at every
# variant, the static tiers run with their positive controls, both judge arms
# run, and the report is rebuilt. Each step stops the chain on a non-zero exit.
#
# PROVIDER is the LLM transport. `deepseek` bills per token and reports its
# token usage, which is what the thinking control reads; `opencode` spends a
# subscription instead and reports no usage, so the control records that it
# could not run. Both are real arms, they just answer different questions.
PROVIDER ?= deepseek
bench: venv
	PYTHONPATH=. $(PY) -m ssrefuse.cli preflight --provider $(PROVIDER) --effort off
	PYTHONPATH=. $(PY) -m ssrefuse.cli validate
	PYTHONPATH=. $(PY) -m ssrefuse.cli probe
	PYTHONPATH=. $(PY) -m ssrefuse.cli scan
	PYTHONPATH=. $(PY) -m ssrefuse.cli judge --provider $(PROVIDER) --effort off  --rounds 2
	PYTHONPATH=. $(PY) -m ssrefuse.cli judge --provider $(PROVIDER) --effort high --rounds 2
	PYTHONPATH=. $(PY) -m ssrefuse.cli report

test: venv
	PYTHONPATH=. $(PY) -m pytest tests -q

clean:
	rm -rf results/probe results/selftest results/*.md results/static-runs.json
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
