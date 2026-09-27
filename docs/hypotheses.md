# What I measured

Claim 1: The combined baseline does not reach both 100% attack block rate and
0% false-positive rate on the test split. Procedure: run
`python bench/run_baselines.py`; verdict comes from `results/reference-baselines`.

Claim 2: The keyword baseline has materially higher false-positive behavior on
hard-negative benign examples than on regular benign examples. Procedure:
inspect the per-family breakdown in the keyword baseline report.

Claim 3: Dataset generation is deterministic. Procedure: generate traces twice
with the same seed and compare SHA-256 hashes of `test.jsonl`.

Verdicts are intentionally left to generated benchmark artifacts rather than
hand-entered prose.
