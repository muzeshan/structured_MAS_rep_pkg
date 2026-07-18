from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path

import yaml
from tqdm.auto import tqdm

from vulhandoff.config import ExperimentConfig
from vulhandoff.llm import create_backend
from vulhandoff.models import CaseSample
from vulhandoff.workflows import (
    run_rq3_freeform_from_handoffs,
    run_rq3_self_refine_from_handoffs,
    run_rq3_structured_from_handoffs,
)

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG = ROOT / "configs/development_frozen_v3_qwen3b.yaml"
DEFAULT_MANIFEST = ROOT / "results/rq3/raw/rq3_corrected_fault_manifest.jsonl"
DEFAULT_OUTPUT = ROOT / "outputs/rq3_corrected_fault_injection_qwen3b"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the corrected RQ3 fault-injection experiment.")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--batch-size", type=int, default=4)
    return parser.parse_args()


def load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def load_completed_keys(output_path: Path) -> set[tuple[str, str, str, str]]:
    if not output_path.exists():
        return set()
    completed: set[tuple[str, str, str, str]] = set()
    for record in load_jsonl(output_path):
        case = record["case"]
        metadata = record.get("metadata", {})
        completed.add((record["system"], case["pair_id"], case["version"], metadata["fault_type"]))
    return completed


def save_records(output_path: Path, generated_records, manifest_items: list[dict]) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("a", encoding="utf-8") as handle:
        for record, item in zip(generated_records, manifest_items):
            payload = record.model_dump(mode="json")
            payload.setdefault("metadata", {})
            payload["metadata"].update(
                {
                    "corrected_fault_semantics": True,
                    "handoff_format": item["handoff_format"],
                    "injection_metadata": item["injection_metadata"],
                }
            )
            handle.write(json.dumps(payload, ensure_ascii=False) + "\n")


def chunks(items: list[dict], size: int):
    for start in range(0, len(items), size):
        yield items[start : start + size]


def main() -> None:
    args = parse_args()
    config_path = args.config.resolve()
    manifest_path = args.manifest.resolve()
    output_path = args.output_dir.resolve() / "records-shard-000-of-001.jsonl"

    if not config_path.exists():
        raise FileNotFoundError(config_path)
    if not manifest_path.exists():
        raise FileNotFoundError(manifest_path)

    config_data = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    config = ExperimentConfig.model_validate(config_data["experiment"])
    manifest = load_jsonl(manifest_path)
    if len(manifest) != 270:
        raise ValueError(f"Expected 270 manifest records, found {len(manifest)}")

    completed = load_completed_keys(output_path)
    pending = [
        item
        for item in manifest
        if (item["system"], item["pair_id"], item["version"], item["fault_type"])
        not in completed
    ]
    print("Manifest conditions:", len(manifest))
    print("Already completed:", len(completed))
    print("Pending conditions:", len(pending))
    print("Pending by system:", Counter(item["system"] for item in pending))
    print("Pending by fault:", Counter(item["fault_type"] for item in pending))
    if not pending:
        print("Corrected RQ3 run is already complete.")
        return

    backend = create_backend(config.model)
    grouped: dict[str, list[dict]] = defaultdict(list)
    for item in pending:
        grouped[item["system"]].append(item)

    for system in ["self_refine", "freeform_mas", "structured_mas"]:
        system_items = grouped.get(system, [])
        if not system_items:
            continue
        print(f"\nRunning {system}: {len(system_items)} conditions")
        progress = tqdm(total=len(system_items), desc=system)
        for batch in chunks(system_items, args.batch_size):
            cases = [CaseSample.model_validate(item["case"]) for item in batch]
            fault_types = [item["fault_type"] for item in batch]
            handoffs = [item["faulted_upstream_handoff"] for item in batch]
            kwargs = dict(
                cases=cases,
                injected_handoffs=handoffs,
                fault_types=fault_types,
                backend=backend,
                config=config,
                repetition=1,
            )
            if system == "self_refine":
                generated = run_rq3_self_refine_from_handoffs(**kwargs)
            elif system == "freeform_mas":
                generated = run_rq3_freeform_from_handoffs(**kwargs)
            else:
                generated = run_rq3_structured_from_handoffs(**kwargs)
            save_records(output_path, generated, batch)
            progress.update(len(batch))
        progress.close()

    final_count = len(load_jsonl(output_path))
    print("\nCorrected RQ3 run complete.")
    print("Result records:", final_count)
    print("Output:", output_path)


if __name__ == "__main__":
    main()
