from __future__ import annotations

import argparse
import json
from pathlib import Path

DEFAULT_EXCLUDED = {"secvuleval::15308::e753a7013efd"}


def main() -> None:
    parser = argparse.ArgumentParser(description="Apply the frozen function-only eligibility exclusion.")
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--exclusion-log", type=Path, default=None)
    args = parser.parse_args()

    pairs = [json.loads(line) for line in args.input.read_text(encoding="utf-8").splitlines() if line.strip()]
    kept = [pair for pair in pairs if pair["pair_id"] not in DEFAULT_EXCLUDED]
    excluded = [pair["pair_id"] for pair in pairs if pair["pair_id"] in DEFAULT_EXCLUDED]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as handle:
        for pair in kept:
            handle.write(json.dumps(pair, ensure_ascii=False) + "\n")

    log_path = args.exclusion_log or args.output.with_name("exclusion_log.json")
    log = [
        {
            "pair_id": pair_id,
            "decision": "exclude",
            "category": "invalid_for_function_only",
            "reason": (
                "The CWE-59 filesystem and symbolic-link behavior is implemented in unseen helper "
                "functions; the supplied function does not expose enough local evidence to establish "
                "the vulnerability or repair."
            ),
        }
        for pair_id in excluded
    ]
    log_path.write_text(json.dumps(log, indent=2), encoding="utf-8")
    print(f"Input pairs: {len(pairs)}")
    print(f"Kept pairs: {len(kept)}")
    print(f"Excluded pairs: {len(excluded)}")
    print(f"Output: {args.output}")


if __name__ == "__main__":
    main()
