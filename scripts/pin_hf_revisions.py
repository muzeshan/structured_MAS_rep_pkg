#!/usr/bin/env python3
"""Resolve mutable Hugging Face refs to immutable commit SHAs in YAML configs."""
from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

import yaml
from huggingface_hub import HfApi


def pin_file(path: Path, api: HfApi) -> list[str]:
    data: dict[str, Any] = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    changes: list[str] = []
    dataset = data.get("dataset")
    if isinstance(dataset, dict) and dataset.get("hf_dataset_id"):
        info = api.dataset_info(dataset["hf_dataset_id"], revision=dataset.get("hf_revision"))
        old = dataset.get("hf_revision")
        dataset["hf_revision"] = info.sha
        changes.append(f"dataset {dataset['hf_dataset_id']}: {old!r} -> {info.sha}")
    for section_name in ["experiment", "faults"]:
        section = data.get(section_name)
        if not isinstance(section, dict):
            continue
        model = section.get("model")
        if isinstance(model, dict) and model.get("model_id") and model.get("backend") != "mock":
            info = api.model_info(model["model_id"], revision=model.get("revision"))
            old = model.get("revision")
            model["revision"] = info.sha
            changes.append(f"model {model['model_id']}: {old!r} -> {info.sha}")
    path.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True), encoding="utf-8")
    return changes


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("configs", nargs="+")
    parser.add_argument("--token")
    args = parser.parse_args()
    api = HfApi(token=args.token)
    for name in args.configs:
        path = Path(name)
        changes = pin_file(path, api)
        print(path)
        for change in changes:
            print(f"  {change}")
        if not changes:
            print("  no Hugging Face resources found")


if __name__ == "__main__":
    main()
