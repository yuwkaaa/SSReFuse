# SSReFuse. Everything runs through the project venv so a system Python upgrade
# cannot change a measurement.
PY := .venv/bin/python
VENV := .venv

.PHONY: help venv validate selftest probe scan report all test clean

help:
	@echo "make venv      - create .venv and install dependencies"
	@echo "make validate  - check the corpus against its source markers"
	@echo "make selftest  - build the sandbox and prove it is hermetic"
	@echo "make probe     - fire the payload catalog at every lab variant"
	@echo "make scan      - run the static detectors with their positive control"
	@echo "make report    - score everything measured so far into results/report.md"
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

all: venv
	PYTHONPATH=. $(PY) -m ssrefuse.cli all

test: venv
	PYTHONPATH=. $(PY) -m pytest tests -q

clean:
	rm -rf results/probe results/selftest results/*.md results/static-runs.json
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
