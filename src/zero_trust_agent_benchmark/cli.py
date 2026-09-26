"""Command line interface for Zero Trust Agent Benchmark."""

from __future__ import annotations

import argparse
import csv
import hashlib
import importlib
import json
import platform
import socket
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from . import __version__
from .baselines import BASELINE_NAMES, get_baseline
from .evaluate import HttpDefense, Report, evaluate, load_traces
from .generator import DEFAULT_SEED, write_traces
from .profile import profile
from .schema import iter_traces


def _utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _run_id() -> str:
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    return f"{stamp}-{socket.gethostname().split('.')[0].lower()[:12]}"


def _load_attr(spec: str) -> Any:
    module_name, sep, attr = spec.partition(":")
    if not sep:
        raise SystemExit("--defense must be module:attr")
    obj: Any = importlib.import_module(module_name)
    for part in attr.split("."):
        obj = getattr(obj, part)
    return obj


def _env() -> dict[str, Any]:
    git_sha = _git_sha(Path.cwd())
    return {
        "timestamp_utc": _utc_now(),
        "zero_trust_agent_benchmark_version": __version__,
        "python": sys.version,
        "platform": platform.platform(),
        "machine": platform.machine(),
        "host": socket.gethostname(),
        "git_sha": git_sha,
    }


def _git_sha(path: Path) -> str | None:
    git_dir = path / ".git"
    if not git_dir.is_dir():
        return None
    head = git_dir / "HEAD"
    if not head.is_file():
        return None
    value = head.read_text(encoding="utf-8").strip()
    if value.startswith("ref: "):
        ref = git_dir / value.removeprefix("ref: ")
        return ref.read_text(encoding="utf-8").strip() if ref.is_file() else None
    return value


def _write_manifest(out: Path) -> None:
    rows = []
    for p in sorted(x for x in out.rglob("*") if x.is_file() and x.name != "manifest.sha256"):
        digest = hashlib.sha256(p.read_bytes()).hexdigest()
        rows.append(f"{digest}  {p.relative_to(out).as_posix()}")
    (out / "manifest.sha256").write_text("\n".join(rows) + "\n", encoding="utf-8")


def _write_trial(out: Path, trial: int, report: Report) -> None:
    data = {"trial": trial, "timestamp_utc": _utc_now(), "report": report.to_dict()}
    path = out / "per-trial-logs" / f"trial-{trial:03d}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_measurements(out: Path, reports: list[Report]) -> None:
    with (out / "measurements.csv").open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(
            fh,
            fieldnames=[
                "trial",
                "timestamp_utc",
                "traces",
                "blocked_attacks",
                "false_positives",
                "leak_count",
                "p95_ms",
                "p99_ms",
            ],
        )
        writer.writeheader()
        for i, report in enumerate(reports, 1):
            writer.writerow(
                {
                    "trial": i,
                    "timestamp_utc": _utc_now(),
                    "traces": report.counts["traces"],
                    "blocked_attacks": report.counts["blocked_attacks"],
                    "false_positives": report.counts["false_positives"],
                    "leak_count": report.metrics["leak_count"],
                    "p95_ms": report.latency_ms.get("p95"),
                    "p99_ms": report.latency_ms.get("p99"),
                }
            )


def _run(args: argparse.Namespace) -> int:
    defense = HttpDefense(args.url) if args.url else _load_attr(args.defense)
    if isinstance(defense, str) and defense in BASELINE_NAMES:
        defense = get_baseline(defense)
    if hasattr(defense, "setup"):
        defense.setup(profile())
    traces = load_traces(args.split, args.traces)
    out = Path(args.out) if args.out else Path("results") / _run_id()
    out.mkdir(parents=True, exist_ok=True)
    reports: list[Report] = []
    for trial in range(1, args.repeats + 1):
        report = evaluate(defense, traces, provide_issued_secrets=not args.no_issued_secrets)
        reports.append(report)
        _write_trial(out, trial, report)
    _write_measurements(out, reports)
    summary = reports[-1].to_dict()
    summary["run"] = {
        "split": args.split,
        "repeats": args.repeats,
        "defense": args.url or args.defense,
        "provide_issued_secrets": not args.no_issued_secrets,
        "timestamp_utc": _utc_now(),
    }
    (out / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (out / "env.json").write_text(
        json.dumps(_env(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    _write_manifest(out)
    print(json.dumps({"out": str(out), "summary": summary["metrics"]}, indent=2))
    return 0


def _validate(args: argparse.Namespace) -> int:
    path = Path(args.path)
    files = sorted(path.glob("*.jsonl")) if path.is_dir() else [path]
    total = 0
    for f in files:
        n = sum(1 for _ in iter_traces(f))
        print(f"{f}: {n} traces")
        total += n
    print(f"validated {total} traces")
    return 0


def _generate_cmd(args: argparse.Namespace) -> int:
    print(json.dumps(write_traces(Path(args.out), args.seed), indent=2))
    return 0


def _profile_cmd(_args: argparse.Namespace) -> int:
    print(json.dumps(profile(), indent=2, sort_keys=True))
    return 0


def _serve_cmd(args: argparse.Namespace) -> int:
    uvicorn.run(_app(args.name), host="127.0.0.1", port=args.port)
    return 0


def _report(args: argparse.Namespace) -> int:
    data = json.loads((Path(args.path) / "summary.json").read_text(encoding="utf-8"))
    print(json.dumps({"counts": data["counts"], "metrics": data["metrics"]}, indent=2))
    return 0


def _app(name: str) -> Starlette:
    defense = get_baseline(name)

    async def decide(request: Request) -> JSONResponse:
        body = await request.json()
        return JSONResponse(defense.decide(body).as_dict())

    return Starlette(routes=[Route("/v1/decide", decide, methods=["POST"])])


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="zero-trust-agent-benchmark")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_gen = sub.add_parser("generate", help="generate deterministic traces")
    p_gen.add_argument("--out", required=True)
    p_gen.add_argument("--seed", type=int, default=DEFAULT_SEED)
    p_gen.set_defaults(func=_generate_cmd)

    p_val = sub.add_parser("validate", help="validate trace JSONL")
    p_val.add_argument("path")
    p_val.set_defaults(func=_validate)

    p_run = sub.add_parser("run", help="evaluate a defense")
    mode = p_run.add_mutually_exclusive_group(required=True)
    mode.add_argument("--defense")
    mode.add_argument("--url")
    p_run.add_argument("--split", choices=["dev", "test"], default="test")
    p_run.add_argument("--traces")
    p_run.add_argument("--out")
    p_run.add_argument("--repeats", type=int, default=30)
    p_run.add_argument(
        "--no-issued-secrets",
        action="store_true",
        help="call on_trace_start with an empty issued_secrets list",
    )
    p_run.set_defaults(func=_run)

    p_rep = sub.add_parser("report", help="print a result summary")
    p_rep.add_argument("path")
    p_rep.set_defaults(func=_report)

    p_prof = sub.add_parser("profile", help="print the public deployment profile")
    p_prof.set_defaults(func=_profile_cmd)

    p_srv = sub.add_parser("serve-baseline", help="serve a baseline over HTTP")
    p_srv.add_argument("--name", choices=BASELINE_NAMES, default="combined")
    p_srv.add_argument("--port", type=int, default=18000)
    p_srv.set_defaults(func=_serve_cmd)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
