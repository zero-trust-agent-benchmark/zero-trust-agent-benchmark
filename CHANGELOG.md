# Changelog

## Unreleased - 2026-09-25

- Added dataset v4 with benign untrusted-origin consequential workflows, benign MCP `secret://` handles, in-policy attack surface reuse, and shortcut audit artifacts; archived dataset v3 under `traces/v3/`.
- Renamed project to **Zero Trust Agent Benchmark** (was AZT-Bench); Python package and CLI renamed to the descriptive names; GitHub home moved to the matching organization.
- Added the `learned_allowlist` baseline and documented dataset v3 in-policy surface-overlap limitations with the v4 reuse plan.

## 0.1.0 dataset v3 - 2026-09-25

- Added `metadata.in_policy` to attack traces and regenerated test with 250
  in-policy and 250 out-of-policy attacks.
- Evaluation reports now include attack block/leak metrics split by in-policy vs
  out-of-policy, with README results regenerated.

## 0.1.0 dataset v2 - 2026-09-25

- Regenerated traces with opaque trace IDs, disjoint dev/test template pools,
  expanded phrasing diversity, shared template identifiers, and profile version v2.
- Strengthened TLA+ scoring model and added dataset leakage/diversity tests.
- Added optional `on_trace_start` issuance-record hook plus the
  `issued_secret_dlp` baseline.
- Varied former marker strings, added benign counter-surfaces, and committed a
  pure-Python overfit check with dataset literal-token API.

## 0.1.0 - 2026-09-25

- Initial reproducible AZT-Bench trace generator, evaluator, baselines, CLI,
  Wilson confidence intervals, documentation, and result artifact layout.
