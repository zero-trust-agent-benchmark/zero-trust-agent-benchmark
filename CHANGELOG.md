# Changelog

## Unreleased - 2026-09-26

- Regenerated dataset v4.1 with the fictional domain changed to `acme.test`; labels, counts, decisions, and baseline rates are unchanged from v4.
- Removed archived shortcut-prone trace files from the package.
- Renamed labels in result files; measured values unchanged.

## 0.1.0 - 2026-09-25

- Added deterministic trace generation, evaluator, baseline defenses, command-line interface, Wilson confidence intervals, documentation, shortcut audit, overfit check, and result artifact layout.
- Added in-policy attack surface reuse, benign untrusted-origin consequential workflows, benign Model Context Protocol `secret://` handles, and hard-negative benign examples.
- Added optional `on_trace_start` issuance-record hook plus the `issued_secret_dlp` baseline.
