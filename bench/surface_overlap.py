from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from zero_trust_agent_benchmark.baselines import _destinations, _path_prefixes  # noqa: E402
from zero_trust_agent_benchmark.evaluate import load_traces  # noqa: E402
from zero_trust_agent_benchmark.schema import Step, Trace  # noqa: E402


def _jaccard(left: set[Any], right: set[Any]) -> float:
    return len(left & right) / len(left | right) if left or right else 1.0


def _arg_key_set(step: Step) -> tuple[str, tuple[str, ...]]:
    return step.tool, tuple(sorted(step.args))


def _surface_tuple(step: Step) -> tuple[str, tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    return (
        step.tool,
        tuple(sorted(_destinations(step.args))),
        tuple(sorted(_path_prefixes(step.args))),
        tuple(sorted(step.args)),
    )


def _steps(traces: list[Trace], *, benign: bool) -> list[Step]:
    if benign:
        return [step for trace in traces if trace.label == "benign" for step in trace.steps]
    return [
        step
        for trace in traces
        if trace.label == "attack" and trace.metadata.get("in_policy") is True
        for step in trace.steps
        if step.malicious
    ]


def compute() -> dict[str, Any]:
    traces = load_traces("test", ROOT / "traces")
    benign_steps = _steps(traces, benign=True)
    malicious_steps = _steps(traces, benign=False)
    benign_destinations = {
        (step.tool, dest) for step in benign_steps for dest in _destinations(step.args)
    }
    malicious_destinations = {
        (step.tool, dest) for step in malicious_steps for dest in _destinations(step.args)
    }
    benign_paths = {
        (step.tool, prefix) for step in benign_steps for prefix in _path_prefixes(step.args)
    }
    malicious_paths = {
        (step.tool, prefix) for step in malicious_steps for prefix in _path_prefixes(step.args)
    }
    benign_arg_keys = {_arg_key_set(step) for step in benign_steps}
    malicious_arg_keys = {_arg_key_set(step) for step in malicious_steps}
    benign_tuples = {_surface_tuple(step) for step in benign_steps}
    malicious_tuples = [_surface_tuple(step) for step in malicious_steps]
    unseen = sum(1 for surface in malicious_tuples if surface not in benign_tuples)
    return {
        "timestamp_utc": datetime.now(UTC).isoformat(),
        "split": "test",
        "scope": "in_policy_malicious_steps_vs_all_benign_steps",
        "counts": {
            "benign_steps": len(benign_steps),
            "in_policy_malicious_steps": len(malicious_steps),
            "benign_destinations": len(benign_destinations),
            "malicious_destinations": len(malicious_destinations),
            "benign_path_prefixes": len(benign_paths),
            "malicious_path_prefixes": len(malicious_paths),
            "benign_arg_key_sets": len(benign_arg_keys),
            "malicious_arg_key_sets": len(malicious_arg_keys),
            "benign_surface_tuples": len(benign_tuples),
            "malicious_surface_tuples": len(set(malicious_tuples)),
        },
        "jaccard": {
            "destinations": _jaccard(malicious_destinations, benign_destinations),
            "path_prefixes": _jaccard(malicious_paths, benign_paths),
            "arg_key_sets": _jaccard(malicious_arg_keys, benign_arg_keys),
            "surface_tuples": _jaccard(set(malicious_tuples), benign_tuples),
        },
        "malicious_surface_tuple_unseen_fraction": unseen / len(malicious_tuples)
        if malicious_tuples
        else 0.0,
    }


def main() -> int:
    out = ROOT / "results" / "surface_overlap.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    data = compute()
    out.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(data, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
