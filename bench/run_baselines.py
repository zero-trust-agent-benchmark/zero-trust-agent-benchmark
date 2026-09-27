from __future__ import annotations

import csv
import hashlib
import json
import platform
import shutil
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from zero_trust_agent_benchmark.baselines import BASELINE_NAMES, get_baseline  # noqa: E402
from zero_trust_agent_benchmark.evaluate import evaluate, load_traces  # noqa: E402
from zero_trust_agent_benchmark.stats import (  # noqa: E402
    bootstrap_quantile_ci,
    mean_t_ci,
    quantile,
)

REPEATS = 30
RESULTS_START = "<!-- BENCHMARK-RESULTS:START -->"
RESULTS_END = "<!-- BENCHMARK-RESULTS:END -->"


def _fmt_rate(metric: dict[str, object]) -> str:
    return f"{float(metric['point']):.3f} [{float(metric['low']):.3f}, {float(metric['high']):.3f}]"


def _latency_trials(values: list[float]) -> dict[str, object]:
    return {
        "count": len(values),
        "mean_ci": mean_t_ci(values).as_dict(),
        "p50": quantile(values, 0.50),
        "p95": quantile(values, 0.95),
        "p99": quantile(values, 0.99),
        "p95_ci": bootstrap_quantile_ci(values, 0.95, resamples=500, seed=101).as_dict(),
        "p99_ci": bootstrap_quantile_ci(values, 0.99, resamples=500, seed=103).as_dict(),
    }


def _latency_distribution(values: list[float]) -> dict[str, object]:
    return {
        "count": len(values),
        "p50": quantile(values, 0.50),
        "p95": quantile(values, 0.95),
        "p99": quantile(values, 0.99),
    }


def main() -> int:
    traces = load_traces("test", ROOT / "traces")
    out = ROOT / "results" / "reference-baselines"
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True, exist_ok=True)
    logs = out / "per-trial-logs"
    logs.mkdir(parents=True, exist_ok=True)
    summary: dict[str, object] = {"split": "test", "repeats": REPEATS, "baselines": {}}
    rows = []
    for name in BASELINE_NAMES:
        elapsed_ms: list[float] = []
        decision_latency_ms: list[float] = []
        data: dict[str, object] | None = None
        for trial in range(1, REPEATS + 1):
            started = time.perf_counter()
            report = evaluate(get_baseline(name), traces)
            elapsed = (time.perf_counter() - started) * 1000.0
            timestamp = datetime.now(UTC).isoformat()
            elapsed_ms.append(elapsed)
            decision_latency_ms.extend(result.latency_ms for result in report.step_results)
            data = report.to_dict()
            (logs / f"{name}-trial-{trial:03d}.json").write_text(
                json.dumps(
                    {
                        "baseline": name,
                        "trial": trial,
                        "timestamp_utc": timestamp,
                        "elapsed_ms": elapsed,
                        "report": data,
                    },
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
        if data is None:
            raise RuntimeError(f"no trials ran for {name}")
        aggregate = {
            "report": data,
            "elapsed_ms": _latency_trials(elapsed_ms),
            "decision_latency_ms": _latency_distribution(decision_latency_ms),
        }
        (out / f"{name}.json").write_text(
            json.dumps(aggregate, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        summary["baselines"][name] = aggregate  # type: ignore[index]
        rows.append(
            (
                name,
                data["metrics"]["block_rate"],  # type: ignore[index]
                data["metrics"]["attack_policy_slices"]["in_policy"]["block_rate"],  # type: ignore[index]
                data["metrics"]["attack_policy_slices"]["out_of_policy"]["block_rate"],  # type: ignore[index]
                data["metrics"]["false_positive_rate"],  # type: ignore[index]
                data["metrics"]["leak_count"],  # type: ignore[index]
                aggregate["elapsed_ms"]["mean_ci"],  # type: ignore[index]
                aggregate["decision_latency_ms"]["p95"],  # type: ignore[index]
            )
        )
    summary["timestamp_utc"] = datetime.now(UTC).isoformat()
    (out / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    with (out / "measurements.csv").open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(
            [
                "baseline",
                "block_rate",
                "in_policy_block_rate",
                "out_of_policy_block_rate",
                "false_positive_rate",
                "leak_count",
                "mean_ms",
            ]
        )
        for name, block, in_block, out_block, fpr, leaks, mean_ci, _p95_ms in rows:
            writer.writerow(
                [
                    name,
                    block["point"],  # type: ignore[index]
                    in_block["point"],  # type: ignore[index]
                    out_block["point"],  # type: ignore[index]
                    fpr["point"],  # type: ignore[index]
                    leaks,
                    mean_ci["point"],  # type: ignore[index]
                ]
            )
    env = {
        "timestamp_utc": datetime.now(UTC).isoformat(),
        "python": sys.version,
        "platform": platform.platform(),
        "trace_count": len(traces),
    }
    (out / "env.json").write_text(
        json.dumps(env, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    manifest = []
    for path in sorted(p for p in out.rglob("*") if p.is_file() and p.name != "manifest.sha256"):
        manifest.append(
            f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(out).as_posix()}"
        )
    (out / "manifest.sha256").write_text("\n".join(manifest) + "\n", encoding="utf-8")
    readme = ROOT / "README.md"
    readme_text = readme.read_text(encoding="utf-8")
    md_lines = [
        RESULTS_START,
        "| Baseline | Overall block | In-policy block | Out-of-policy block | "
        "False positive rate | Leaks | 95th percentile decision latency (ms) |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for name, block, in_block, out_block, fpr, leak_count, _mean_ci, p95_ms in rows:
        md_lines.append(
            f"| {name} | {_fmt_rate(block)} | {_fmt_rate(in_block)} | "
            f"{_fmt_rate(out_block)} | {_fmt_rate(fpr)} | {leak_count} | "
            f"{float(p95_ms):.3f} |"
        )
    md_lines.extend(
        [
            "",
            f"Generated by `python bench/run_baselines.py` on the dataset v4.1 test split "
            f"with {REPEATS} latency repeats.",
            RESULTS_END,
        ]
    )
    start = readme_text.index(RESULTS_START)
    end = readme_text.index(RESULTS_END) + len(RESULTS_END)
    readme.write_text(
        readme_text[:start] + "\n".join(md_lines) + readme_text[end:],
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
