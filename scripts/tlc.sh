#!/usr/bin/env bash
set -euo pipefail

if ! command -v java >/dev/null 2>&1; then
  echo "SKIP: java not found; skipping TLC"
  exit 0
fi

TLA_JAR="${TLA_JAR:-tools/tla2tools.jar}"
if [[ ! -f "$TLA_JAR" ]]; then
  echo "SKIP: tla2tools.jar not found; skipping TLC"
  exit 0
fi

java -XX:+UseParallelGC -cp "$TLA_JAR" tlc2.TLC -workers auto -config specs/Scoring.cfg specs/Scoring.tla
