from __future__ import annotations

import argparse
import json
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from vulhandoff.analysis import generate_all_results
from vulhandoff.annotation import (
    annotation_agreement,
    export_adjudication_sheet,
    export_annotation_packets,
    summarize_adjudicated_annotations,
)
from vulhandoff.config import (
    load_analysis_config,
    load_dataset_config,
    load_experiment_config,
    load_fault_config,
    load_yaml,
)
from vulhandoff.data import dataset_summary, load_pairs, pair_to_cases, prepare_dataset
from vulhandoff.faults import make_faults, run_fault_experiments
from vulhandoff.prompts import (
    final_adjudication_prompt,
    freeform_analysis_prompt,
    freeform_refutation_prompt,
    self_analysis_prompt,
    self_critique_prompt,
    structured_analysis_prompt,
    structured_refutation_prompt,
)
from vulhandoff.utils import ensure_dir, file_sha256
from vulhandoff.workflows import PROTOCOL_HASH, run_experiments


def command_prepare(args: argparse.Namespace) -> None:
    config = load_dataset_config(args.config)
    manifest = prepare_dataset(config)
    print(json.dumps(manifest, indent=2))


def command_inspect(args: argparse.Namespace) -> None:
    pairs = load_pairs(args.pairs)
    summary = dataset_summary(pairs)
    projects = {pair.project for pair in pairs if pair.project}
    summary.update(
        {
            "file": str(args.pairs),
            "sha256": file_sha256(args.pairs),
            "project_examples": sorted(projects)[:20],
        }
    )
    print(json.dumps(summary, indent=2))


def _override_sharding(config: Any, args: argparse.Namespace) -> Any:
    if getattr(args, "shard_index", None) is not None:
        config.shard_index = args.shard_index
    if getattr(args, "num_shards", None) is not None:
        config.num_shards = args.num_shards
    if getattr(args, "overwrite", False):
        config.overwrite = True
    return config


def command_run(args: argparse.Namespace) -> None:
    config = _override_sharding(load_experiment_config(args.config), args)
    output = run_experiments(config)
    print(output)


def command_faults(args: argparse.Namespace) -> None:
    config = _override_sharding(load_fault_config(args.config), args)
    output = run_fault_experiments(config)
    print(output)


def command_analyze(args: argparse.Namespace) -> None:
    config = load_analysis_config(args.config)
    outputs = generate_all_results(config)
    print(json.dumps({key: str(value) for key, value in outputs.items()}, indent=2))


def command_export_annotations(args: argparse.Namespace) -> None:
    systems = [item.strip() for item in args.systems.split(",") if item.strip()] if args.systems else None
    versions = [item.strip() for item in args.versions.split(",") if item.strip()] if args.versions else None
    paths = export_annotation_packets(
        results_path=args.results,
        pairs_path=args.pairs,
        output_dir=args.output_dir,
        seed=args.seed,
        systems=systems,
        versions=versions,
    )
    print("\n".join(str(path) for path in paths))


def command_annotation_agreement(args: argparse.Namespace) -> None:
    merged, agreement = annotation_agreement(args.annotator_a, args.annotator_b, args.key)
    output = ensure_dir(args.output_dir)
    merged_path = output / "merged_annotations.csv"
    agreement_path = output / "annotation_agreement.csv"
    adjudication_path = output / "adjudication_sheet.csv"
    merged.to_csv(merged_path, index=False)
    agreement.to_csv(agreement_path, index=False)
    export_adjudication_sheet(merged, str(adjudication_path))
    print(json.dumps({
        "merged": str(merged_path),
        "agreement": str(agreement_path),
        "adjudication": str(adjudication_path),
    }, indent=2))


def command_summarize_annotations(args: argparse.Namespace) -> None:
    _, summary = summarize_adjudicated_annotations(
        merged_path=args.merged,
        key_path=args.key,
        output_dir=args.output_dir,
        adjudicated_path=args.adjudicated,
        results_path=args.results,
    )
    print(summary.to_string(index=False))


def _placeholder_with_token_budget(tokenizer: Any, budget: int) -> str:
    """Create a deterministic placeholder close to a requested token budget."""
    if budget <= 0:
        return ""
    unit = " evidence [L0001-L0001]"
    text = unit * max(1, budget)
    ids = tokenizer(text, add_special_tokens=False)["input_ids"][:budget]
    return tokenizer.decode(ids, skip_special_tokens=True)


def command_preflight(args: argparse.Namespace) -> None:
    raw = load_yaml(args.config)
    is_experiment = "experiment" in raw
    if is_experiment:
        config = load_experiment_config(args.config)
        pairs_path = config.prepared_pairs
        model = config.model
        budget = config.budget
    elif "faults" in raw:
        config = load_fault_config(args.config)
        pairs_path = config.prepared_pairs
        model = config.model
        budget = config.budget
    else:
        raise ValueError("Preflight expects an experiment or faults config")
    pairs = load_pairs(pairs_path)
    cases = [case for pair in pairs for case in pair_to_cases(pair)]
    if not cases:
        raise ValueError("No cases available")
    code_characters = [len(case.code) for case in cases]
    code_lines = [len(case.code.splitlines()) for case in cases]
    result: dict[str, Any] = {
        "pairs": len(pairs),
        "versions": len(cases),
        "model_id": model.model_id,
        "model_revision": model.revision,
        "backend": model.backend,
        "max_code_chars": max(code_characters),
        "max_code_lines": max(code_lines),
        "mean_code_chars": sum(code_characters) / len(code_characters),
        "protocol_hash": PROTOCOL_HASH,
    }
    if is_experiment:
        result["expected_result_records"] = (
            len(cases) * len(config.systems) * config.repetitions
        )
        result["expected_generation_calls"] = (
            len(cases) * len(config.systems) * 3 * config.repetitions
        )
    else:
        generated_faults = make_faults(cases, config.fault_types)
        result["generated_fault_instances"] = len(generated_faults)
        result["expected_result_records"] = (
            len(generated_faults) * len(config.handoff_modes) * config.repetitions
        )
        result["expected_generation_calls"] = (
            len(generated_faults) * len(config.handoff_modes) * 2 * config.repetitions
        )
    if model.backend != "mock":
        from transformers import AutoTokenizer

        tokenizer = AutoTokenizer.from_pretrained(
            model.model_id,
            revision=model.revision,
            trust_remote_code=model.trust_remote_code,
        )
        analysis_placeholder = _placeholder_with_token_budget(tokenizer, budget.analysis)
        critique_placeholder = _placeholder_with_token_budget(tokenizer, budget.critique)
        stage_lengths: dict[str, list[int]] = {
            "stage1": [],
            "stage2": [],
            "stage3": [],
        }

        def rendered_length(conversation: list[dict[str, str]]) -> int:
            prompt = tokenizer.apply_chat_template(
                conversation, tokenize=False, add_generation_prompt=True
            )
            return len(tokenizer(prompt, add_special_tokens=False)["input_ids"])

        for case in cases:
            if is_experiment:
                stage_lengths["stage1"].extend(
                    rendered_length(conversation)
                    for conversation in [
                        self_analysis_prompt(case),
                        freeform_analysis_prompt(case),
                        structured_analysis_prompt(case),
                    ]
                )
                stage_lengths["stage2"].extend(
                    rendered_length(conversation)
                    for conversation in [
                        self_critique_prompt(case, analysis_placeholder),
                        freeform_refutation_prompt(case, analysis_placeholder),
                        structured_refutation_prompt(
                            case, {"raw_placeholder": analysis_placeholder}
                        ),
                    ]
                )
                stage_lengths["stage3"].extend(
                    rendered_length(conversation)
                    for conversation in [
                        final_adjudication_prompt(
                            case,
                            analysis_placeholder,
                            critique_placeholder,
                            "free-form preflight",
                        ),
                        final_adjudication_prompt(
                            case,
                            {"raw_placeholder": analysis_placeholder},
                            {"raw_placeholder": critique_placeholder},
                            "structured preflight",
                        ),
                    ]
                )
            else:
                # Fault runs begin with an injected handoff and therefore use only
                # refutation and adjudication generations.
                stage_lengths["stage2"].extend(
                    rendered_length(conversation)
                    for conversation in [
                        freeform_refutation_prompt(case, analysis_placeholder),
                        structured_refutation_prompt(
                            case, {"raw_placeholder": analysis_placeholder}
                        ),
                    ]
                )
                stage_lengths["stage3"].extend(
                    rendered_length(conversation)
                    for conversation in [
                        final_adjudication_prompt(
                            case,
                            analysis_placeholder,
                            critique_placeholder,
                            "fault free-form preflight",
                        ),
                        final_adjudication_prompt(
                            case,
                            {"raw_placeholder": analysis_placeholder},
                            {"raw_placeholder": critique_placeholder},
                            "fault structured preflight",
                        ),
                    ]
                )

        overflow_total = 0
        for stage_name, lengths in stage_lengths.items():
            if not lengths:
                continue
            overflow = sum(length > model.max_input_tokens for length in lengths)
            overflow_total += overflow
            result[f"max_{stage_name}_prompt_tokens"] = max(lengths)
            result[f"mean_{stage_name}_prompt_tokens"] = sum(lengths) / len(lengths)
            result[f"{stage_name}_prompt_overflow_count"] = overflow
        result["max_input_tokens"] = model.max_input_tokens
        result["prompt_overflow_count_total"] = overflow_total
        result["preflight_note"] = (
            "Stage-2/3 values use deterministic placeholders at the configured output-token "
            "ceilings; the runtime still performs an exact no-truncation check on every prompt."
        )
        if overflow_total:
            raise ValueError(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))


def command_freeze(args: argparse.Namespace) -> None:
    destination = ensure_dir(args.output_dir)
    for config_path in args.configs:
        source = Path(config_path)
        shutil.copy2(source, destination / source.name)
    metadata = {
        "protocol_hash": PROTOCOL_HASH,
        "python": sys.version,
        "platform": platform.platform(),
        "config_hashes": {
            Path(path).name: file_sha256(path) for path in args.configs
        },
    }
    try:
        metadata["pip_freeze"] = subprocess.check_output(
            [sys.executable, "-m", "pip", "freeze"], text=True
        ).splitlines()
    except Exception as exc:
        metadata["pip_freeze_error"] = str(exc)
    (destination / "frozen_protocol.json").write_text(
        json.dumps(metadata, indent=2), encoding="utf-8"
    )
    print(destination / "frozen_protocol.json")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vulhandoff")
    subparsers = parser.add_subparsers(dest="command", required=True)

    prepare = subparsers.add_parser("prepare", help="Prepare paired vulnerability data")
    prepare.add_argument("--config", required=True)
    prepare.set_defaults(func=command_prepare)

    inspect = subparsers.add_parser("inspect", help="Inspect a prepared pair file")
    inspect.add_argument("--pairs", required=True)
    inspect.set_defaults(func=command_inspect)

    preflight = subparsers.add_parser("preflight", help="Validate prompt lengths and inputs")
    preflight.add_argument("--config", required=True)
    preflight.set_defaults(func=command_preflight)

    run = subparsers.add_parser("run", help="Run RQ1/RQ2 workflows")
    run.add_argument("--config", required=True)
    run.add_argument("--shard-index", type=int)
    run.add_argument("--num-shards", type=int)
    run.add_argument("--overwrite", action="store_true")
    run.set_defaults(func=command_run)

    faults = subparsers.add_parser("faults", help="Run RQ3 controlled-fault workflows")
    faults.add_argument("--config", required=True)
    faults.add_argument("--shard-index", type=int)
    faults.add_argument("--num-shards", type=int)
    faults.add_argument("--overwrite", action="store_true")
    faults.set_defaults(func=command_faults)

    analyze = subparsers.add_parser("analyze", help="Generate result tables, tests, and figures")
    analyze.add_argument("--config", required=True)
    analyze.set_defaults(func=command_analyze)

    export = subparsers.add_parser("export-annotations", help="Create blinded RQ2 annotation packets")
    export.add_argument("--results", required=True)
    export.add_argument("--pairs", required=True)
    export.add_argument("--output-dir", required=True)
    export.add_argument("--systems", help="Comma-separated system filter")
    export.add_argument("--versions", help="Comma-separated version filter")
    export.add_argument("--seed", type=int, default=20260712)
    export.set_defaults(func=command_export_annotations)

    agreement = subparsers.add_parser("annotation-agreement", help="Compute agreement and create adjudication sheet")
    agreement.add_argument("--annotator-a", required=True)
    agreement.add_argument("--annotator-b", required=True)
    agreement.add_argument("--key")
    agreement.add_argument("--output-dir", required=True)
    agreement.set_defaults(func=command_annotation_agreement)

    summarize = subparsers.add_parser("summarize-annotations", help="Summarize resolved manual annotations")
    summarize.add_argument("--merged", required=True)
    summarize.add_argument("--key", required=True)
    summarize.add_argument("--adjudicated")
    summarize.add_argument("--results", help="Experiment results used to associate ratings with final correctness")
    summarize.add_argument("--output-dir", required=True)
    summarize.set_defaults(func=command_summarize_annotations)

    freeze = subparsers.add_parser("freeze-configs", help="Snapshot configs, hashes, and environment")
    freeze.add_argument("--configs", nargs="+", required=True)
    freeze.add_argument("--output-dir", required=True)
    freeze.set_defaults(func=command_freeze)
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
