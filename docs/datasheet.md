# Dataset Datasheet

## Motivation

The dataset measures whether zero-trust controls can defend tool-using agents
against realistic classes of malicious tool-call pressure.

## Composition

v0.1.0 dataset v4 contains 500 dev traces and 1000 test traces. Test is balanced
at 500 attack and 500 benign traces. Of the 500 test attacks, 250 are marked
`metadata.in_policy=true`: valid SVID/attestation, adequate configured scopes,
and only allowlisted destinations. The other 250 remain out-of-policy. All
secrets are synthetic random canaries in realistic formats. Dataset v3 remains
archived under `traces/v3/` with its original files for reproducibility.

## Collection process

Traces are generated deterministically from templates and pseudorandom seeds.
Dev and test use disjoint template identifiers and host pools. Dataset v4 keeps
the v3 diversity controls and adds benign workflows that read untrusted content
before consequential actions, pass `secret://` broker handles to MCP tools, run
scoped devops mutations, and reuse in-policy attack tool/host/path/argument
surfaces in benign traces.

## Surface overfit check

`bench/overfit_check.py` trains a pure-Python bag-of-tokens logistic regression
on dev split request-visible fields only, then evaluates on test. This is not a
defense baseline; it measures remaining surface-label leakage.

Latest committed v4 run (`results/overfit_check.json`, 2026-09-25):

| Model | Dev accuracy | Test accuracy | Majority baseline |
|---|---:|---:|---:|
| Bag-of-tokens logistic | 0.720 | 0.732 | 0.500 |

The score remains above chance because some benchmark-relevant surfaces, such as
untrusted retrieved-document origins and genuinely unusual requests, are
intentionally correlated with attacks. It is far below a literal-marker oracle
and should be tracked as the generator evolves.

## Shortcut and surface audit

`bench/shortcut_audit.py` enumerates request-visible single features and pairs
and flags disallowed shortcuts when in-policy attack recall is at least 20% and
benign FPR is at most 2%. Intended content signals are still reported but not
classified as shortcuts: control-token grammar with zero reasoning, malformed
raw tool frames, poisoned tool descriptions/Unicode format controls, explicit
injection language, and issued-secret data-flow indicators. Out-of-policy
identity, attestation, scope, and egress violations are likewise reported as
policy exceptions because they define the out-of-policy split.

| Feature | v3 in-policy recall / benign FPR | v4 in-policy recall / benign FPR | v4 status |
|---|---:|---:|---|
| Untrusted origin + egress | 0.820 / 0.000 | 0.820 / 0.456 | ok |
| Untrusted origin + high/critical risk | 0.260 / 0.000 | 0.260 / 0.294 | ok |
| `secret://` in an MCP call | 0.240 / 0.000 | 0.240 / 0.150 | ok |
| Novel full surface vs test benign | 0.820 / 0.022 | 0.000 / 0.032 | ok |
| `http.post` with `body,request_id,url` | 0.200 / 0.000 | 0.200 / 0.030 | ok |

Summary: v3 has 9 disallowed shortcuts under this audit; v4 has 0. v4 still
reports 9 intended content-signal features and 4 out-of-policy exception
features.

## In-policy surface overlap

`bench/surface_overlap.py` measures test-split in-policy malicious steps against
test benign steps using request-visible surfaces. Latest committed v4 run
(`results/surface_overlap.json`, 2026-09-25):

| Surface | Jaccard similarity |
|---|---:|
| `(tool, destination host)` | 0.462 |
| `(tool, path prefix)` | 0.500 |
| `(tool, argument-key set)` | 0.400 |

41.9% of complete `(tool, hosts, path prefixes, argument keys)` surface tuples
overlap, and 0.0% of in-policy malicious steps have a complete surface tuple
that never appears in any benign test step.

## Intended use

Defensive evaluation, regression testing, and comparative benchmarking of
zero-trust agent controls.

## Known limitations

Synthetic traces cannot cover every real application. Scores should be reported
with Wilson intervals and interpreted as benchmark performance, not a guarantee.
Dataset v4 removes the measured v3 structural shortcuts, but it remains a
synthetic benchmark: intended content/data-flow signals are deliberately present,
and future versions should add more application domains while continuing to run
the shortcut audit.

Dataset v4 attack `context.content` often narrates the attack instead of showing
the kind of payload a model would actually receive. This can reward defenses that
match words from generator text. Dataset v5 should put realistic payloads in
request-visible attack content, including instructions addressed to the model,
poisoned tool descriptions, control-token strings, and encoded secrets. The
narration should move to the non-request-visible `description` field, and benign
hard negatives should use the same vocabulary.
