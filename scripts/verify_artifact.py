from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def main() -> None:
    required = [
        ROOT / "src/vulhandoff/prompts.py",
        ROOT / "src/vulhandoff/workflows.py",
        ROOT / "configs/development_frozen_v3_qwen3b.yaml",
        ROOT / "results/clean/record_level_results.csv",
        ROOT / "results/rq3/raw/records-shard-000-of-001.jsonl",
        ROOT / "results/rq3/raw/rq3_corrected_fault_manifest.jsonl",
        ROOT / "paper/main.tex",
        ROOT / "paper/main.pdf",
    ]
    missing = [str(path.relative_to(ROOT)) for path in required if not path.exists()]
    if missing:
        raise SystemExit(f"Missing required files: {missing}")

    rq3 = load_jsonl(ROOT / "results/rq3/raw/records-shard-000-of-001.jsonl")
    manifest = load_jsonl(ROOT / "results/rq3/raw/rq3_corrected_fault_manifest.jsonl")
    assert len(rq3) == 270
    assert len(manifest) == 270
    assert Counter(row["system"] for row in rq3) == Counter(
        {"self_refine": 90, "freeform_mas": 90, "structured_mas": 90}
    )
    assert Counter(row["metadata"]["fault_type"] for row in rq3) == Counter(
        {"verdict_inversion": 90, "evidence_deletion": 90, "evidence_corruption": 90}
    )
    print("Artifact structure is complete.")
    for path in required:
        print(f"{sha256(path)}  {path.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
