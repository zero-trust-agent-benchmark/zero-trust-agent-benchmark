from __future__ import annotations

import argparse
import json
from pathlib import Path

from zero_trust_agent_benchmark.stats import wilson


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--k", type=int, required=True)
    parser.add_argument("--n", type=int, required=True)
    parser.add_argument("--out")
    args = parser.parse_args()
    result = {"k": args.k, "n": args.n, **wilson(args.k, args.n).as_dict()}
    text = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
    else:
        print(text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
