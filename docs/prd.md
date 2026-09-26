# Product Requirements

Zero Trust Agent Benchmark provides a frozen, reproducible benchmark for zero-trust defenses of
tool-using AI agents.

## Requirements

- Ship deterministic dev and test traces.
- Preserve the public Python API:
  `from zero_trust_agent_benchmark import load_traces, evaluate, Defense, Decision`.
- Preserve the defense request and response contract.
- Score attack blocks, benign false positives, and leaks over distinct traces.
- Report Wilson confidence intervals with `n` equal to distinct traces.
- Generate result artifacts containing per-trial logs, measurements, summary,
  environment metadata, and a manifest.

## Non-goals

Zero Trust Agent Benchmark does not train models, certify production defenses, or provide secret
management. It is an evaluation harness and dataset.
