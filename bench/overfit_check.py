from __future__ import annotations

import argparse
import json
import math
import re
import sys
from collections import Counter
from dataclasses import asdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from zero_trust_agent_benchmark.evaluate import load_traces  # noqa: E402
from zero_trust_agent_benchmark.schema import Trace  # noqa: E402

TOKEN_RE = re.compile(r"[a-z0-9_.:-]{3,}", re.IGNORECASE)


def _visible_trace_text(trace: Trace) -> str:
    history: list[dict[str, Any]] = []
    chunks: list[str] = []
    for step in trace.steps:
        req = {
            "trace_id": trace.trace_id,
            "step": step.step,
            "agent": asdict(trace.agent),
            "tool": step.tool,
            "args": step.args,
            "context": step.context,
            "history": list(history),
        }
        chunks.append(json.dumps(req, sort_keys=True, ensure_ascii=False))
        history.append({"step": step.step, "tool": step.tool, "decision": "allow"})
    return "\n".join(chunks)


def _features(trace: Trace) -> Counter[str]:
    text = _visible_trace_text(trace).lower()
    return Counter(TOKEN_RE.findall(text))


def _score(weights: dict[str, float], features: Counter[str], bias: float) -> float:
    return bias + math.fsum(weights.get(token, 0.0) * count for token, count in features.items())


def _sigmoid(value: float) -> float:
    if value >= 0:
        z = math.exp(-value)
        return 1.0 / (1.0 + z)
    z = math.exp(value)
    return z / (1.0 + z)


def _train(
    rows: list[tuple[Counter[str], int]], *, epochs: int = 40, lr: float = 0.04, l2: float = 0.0005
) -> tuple[dict[str, float], float]:
    weights: dict[str, float] = {}
    bias = 0.0
    for _ in range(epochs):
        for features, label in rows:
            pred = _sigmoid(_score(weights, features, bias))
            err = pred - label
            bias -= lr * err
            norm = max(1.0, math.sqrt(math.fsum(count * count for count in features.values())))
            for token, count in features.items():
                old = weights.get(token, 0.0)
                weights[token] = old - lr * (err * count / norm + l2 * old)
    return weights, bias


def _accuracy(
    weights: dict[str, float], bias: float, rows: list[tuple[Counter[str], int]]
) -> float:
    correct = 0
    for features, label in rows:
        pred = 1 if _score(weights, features, bias) >= 0 else 0
        correct += int(pred == label)
    return correct / len(rows)


def _top(weights: dict[str, float], reverse: bool) -> list[dict[str, float | str]]:
    ordered = sorted(weights.items(), key=lambda item: item[1], reverse=reverse)[:20]
    return [{"token": token, "weight": weight} for token, weight in ordered]


def run(path: Path) -> dict[str, Any]:
    traces = load_traces(None, path)
    dev = [(t, 1 if t.label == "attack" else 0) for t in traces if t.split == "dev"]
    test = [(t, 1 if t.label == "attack" else 0) for t in traces if t.split == "test"]
    dev_rows = [(_features(trace), label) for trace, label in dev]
    test_rows = [(_features(trace), label) for trace, label in test]
    weights, bias = _train(dev_rows)
    majority = max(sum(label for _trace, label in test), len(test) // 2) / len(test)
    return {
        "model": "pure-python bag-of-tokens logistic regression",
        "features": "request-visible fields only",
        "dev_traces": len(dev_rows),
        "test_traces": len(test_rows),
        "dev_accuracy": _accuracy(weights, bias, dev_rows),
        "test_accuracy": _accuracy(weights, bias, test_rows),
        "majority_baseline": majority,
        "top_attack_tokens": _top(weights, True),
        "top_benign_tokens": _top(weights, False),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--traces", default=str(ROOT / "traces"))
    parser.add_argument("--out", default=str(ROOT / "results" / "overfit_check.json"))
    args = parser.parse_args(argv)
    result = run(Path(args.traces))
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
