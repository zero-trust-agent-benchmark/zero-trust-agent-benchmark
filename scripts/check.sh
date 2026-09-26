#!/usr/bin/env bash
set -euo pipefail

python -m pip install -q -e ".[dev]"
ruff check .
ruff format --check .
mypy src
pytest -q --cov=zero_trust_agent_benchmark --cov-report=term-missing --cov-fail-under=85
bash scripts/tlc.sh
