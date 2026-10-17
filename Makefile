# make test        unit tests (Python + Node)
# make bench       offline SPABench run (static phase + value flow + source maps); needs SPABENCH_DIR or ../SPAbench
# make install     Python package + value-flow sidecar dependencies
PY ?= python

install:
	$(PY) -m pip install -e .
	cd analysis && npm ci --ignore-scripts

test: test-py test-node

test-py:
	$(PY) -W error::ResourceWarning -m unittest discover -s tests

test-node:
	cd analysis && node --test test/analyze.test.js

bench:
	$(PY) tools/offline_bench.py --sourcemaps --json results/offline_bench.json

.PHONY: install test test-py test-node bench
