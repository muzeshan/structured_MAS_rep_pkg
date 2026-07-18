from __future__ import annotations

import json
import platform
import sys
from pathlib import Path
from typing import Any, Callable

from tqdm.auto import tqdm

import vulhandoff.parsing as parsing_module
import vulhandoff.prompts as prompts_module

from vulhandoff.config import ExperimentConfig
from vulhandoff.data import load_pairs, pair_to_cases
from vulhandoff.llm import ChatBackend, create_backend
from vulhandoff.models import (
    AnalysisHandoff,
    CaseSample,
    ExperimentRecord,
    GenerationResult,
    RefutationHandoff,
    StageRecord,
    Verdict,
)
from vulhandoff.parsing import (
    normalize_freeform_handoff,
    parse_analysis,
    parse_final,
    parse_refutation,
)
from vulhandoff.prompts import (
    BASE_POLICY,
    analysis_schema,
    final_adjudication_prompt,
    final_schema,
    freeform_analysis_prompt,
    freeform_refutation_prompt,
    refutation_schema,
    self_analysis_prompt,
    self_critique_prompt,
    structured_analysis_prompt,
    structured_refutation_prompt,
)
from vulhandoff.utils import append_jsonl, ensure_dir, read_jsonl, stable_hash


PROTOCOL_HASH = stable_hash(
    Path(__file__).read_text(encoding="utf-8"),
    Path(prompts_module.__file__).read_text(encoding="utf-8"),
    Path(parsing_module.__file__).read_text(encoding="utf-8"),
    length=16,
)


def _stage(
    name: str,
    generation: GenerationResult,
    parsed: Any = None,
    parse_error: str | None = None,
) -> StageRecord:
    if hasattr(parsed, "model_dump"):
        parsed = parsed.model_dump(mode="json")
    elif parsed is not None and not isinstance(parsed, dict):
        parsed = {"value": parsed}
    return StageRecord(
        stage=name,
        raw_text=generation.text,
        parsed=parsed,
        parse_error=parse_error,
        prompt_tokens=generation.prompt_tokens,
        completion_tokens=generation.completion_tokens,
        latency_seconds=generation.latency_seconds,
    )


def _finalize(record: ExperimentRecord) -> ExperimentRecord:
    record.total_prompt_tokens = sum(item.prompt_tokens for item in record.stages)
    record.total_completion_tokens = sum(item.completion_tokens for item in record.stages)
    record.total_latency_seconds = sum(item.latency_seconds for item in record.stages)
    any_stage_parse_failed = any(item.parse_error for item in record.stages)
    upstream_parse_failed = any(
        item.parse_error for item in record.stages if item.stage != "adjudication"
    )
    record.parse_failed = record.final_report is None
    record.metadata["any_stage_parse_failed"] = any_stage_parse_failed
    record.metadata["upstream_parse_failed"] = upstream_parse_failed
    return record


def _run_id(system: str, config: ExperimentConfig, repetition: int, case_id: str) -> str:
    return stable_hash(
        PROTOCOL_HASH,
        system,
        config.model.model_id,
        config.model.revision,
        config.model.temperature,
        config.model.top_p,
        config.model.do_sample,
        config.budget.model_dump(mode="json"),
        repetition,
        case_id,
        length=40,
    )


def run_self_refine(
    cases: list[CaseSample], backend: ChatBackend, config: ExperimentConfig, repetition: int
) -> list[ExperimentRecord]:
    seed = config.base_seed + repetition * 1000
    first = backend.generate_batch(
        [self_analysis_prompt(case) for case in cases],
        max_new_tokens=config.budget.analysis,
        temperature=config.model.temperature,
        top_p=config.model.top_p,
        do_sample=config.model.do_sample,
        seed=seed + 1,
    )
    second = backend.generate_batch(
        [self_critique_prompt(case, result.text) for case, result in zip(cases, first)],
        max_new_tokens=config.budget.critique,
        temperature=config.model.temperature,
        top_p=config.model.top_p,
        do_sample=config.model.do_sample,
        seed=seed + 2,
    )
    third = backend.generate_batch(
        [
            final_adjudication_prompt(
                case,
                initial.text,
                critique.text,
                "single-agent self-refinement",
            )
            for case, initial, critique in zip(cases, first, second)
        ],
        max_new_tokens=config.budget.adjudication,
        temperature=config.model.temperature,
        top_p=config.model.top_p,
        do_sample=config.model.do_sample,
        seed=seed + 3,
    )
    records: list[ExperimentRecord] = []
    for case, initial, critique, final_generation in zip(cases, first, second, third):
        initial_normalized = normalize_freeform_handoff(initial.text, len(case.code.splitlines()))
        critique_normalized = normalize_freeform_handoff(critique.text, len(case.code.splitlines()))
        final_report, final_error = parse_final(final_generation.text)
        record = ExperimentRecord(
            run_id=_run_id("self_refine", config, repetition, case.case_id),
            system="self_refine",
            model=config.model.model_id,
            model_revision=config.model.revision,
            repetition=repetition,
            seed=seed,
            case=case,
            stages=[
                _stage("analysis", initial, initial_normalized),
                _stage("self_critique", critique, critique_normalized),
                _stage("adjudication", final_generation, final_report, final_error),
            ],
            final_report=final_report,
            metadata={"protocol_hash": PROTOCOL_HASH},
        )
        records.append(_finalize(record))
    return records


def run_freeform_mas(
    cases: list[CaseSample], backend: ChatBackend, config: ExperimentConfig, repetition: int
) -> list[ExperimentRecord]:
    seed = config.base_seed + repetition * 1000 + 100
    first = backend.generate_batch(
        [freeform_analysis_prompt(case) for case in cases],
        max_new_tokens=config.budget.analysis,
        temperature=config.model.temperature,
        top_p=config.model.top_p,
        do_sample=config.model.do_sample,
        seed=seed + 1,
    )
    second = backend.generate_batch(
        [freeform_refutation_prompt(case, result.text) for case, result in zip(cases, first)],
        max_new_tokens=config.budget.critique,
        temperature=config.model.temperature,
        top_p=config.model.top_p,
        do_sample=config.model.do_sample,
        seed=seed + 2,
    )
    third = backend.generate_batch(
        [
            final_adjudication_prompt(case, analyst.text, refuter.text, "free-form multi-agent")
            for case, analyst, refuter in zip(cases, first, second)
        ],
        max_new_tokens=config.budget.adjudication,
        temperature=config.model.temperature,
        top_p=config.model.top_p,
        do_sample=config.model.do_sample,
        seed=seed + 3,
    )
    records: list[ExperimentRecord] = []
    for case, analyst, refuter, final_generation in zip(cases, first, second, third):
        analyst_normalized = normalize_freeform_handoff(analyst.text, len(case.code.splitlines()))
        refuter_normalized = normalize_freeform_handoff(refuter.text, len(case.code.splitlines()))
        final_report, final_error = parse_final(final_generation.text)
        record = ExperimentRecord(
            run_id=_run_id("freeform_mas", config, repetition, case.case_id),
            system="freeform_mas",
            model=config.model.model_id,
            model_revision=config.model.revision,
            repetition=repetition,
            seed=seed,
            case=case,
            stages=[
                _stage("analyst", analyst, analyst_normalized),
                _stage("refuter", refuter, refuter_normalized),
                _stage("adjudication", final_generation, final_report, final_error),
            ],
            final_report=final_report,
            metadata={"protocol_hash": PROTOCOL_HASH},
        )
        records.append(_finalize(record))
    return records


def run_structured_mas(
    cases: list[CaseSample], backend: ChatBackend, config: ExperimentConfig, repetition: int
) -> list[ExperimentRecord]:
    seed = config.base_seed + repetition * 1000 + 200
    first = backend.generate_batch(
        [structured_analysis_prompt(case) for case in cases],
        max_new_tokens=config.budget.analysis,
        temperature=config.model.temperature,
        top_p=config.model.top_p,
        do_sample=config.model.do_sample,
        seed=seed + 1,
    )
    analyses: list[AnalysisHandoff] = []
    analysis_errors: list[str | None] = []
    for case, generation in zip(cases, first):
        parsed, error = parse_analysis(generation.text)
        if parsed is None:
            parsed = normalize_freeform_handoff(generation.text, len(case.code.splitlines()))
        analyses.append(parsed)
        analysis_errors.append(error)
    second = backend.generate_batch(
        [structured_refutation_prompt(case, analysis) for case, analysis in zip(cases, analyses)],
        max_new_tokens=config.budget.critique,
        temperature=config.model.temperature,
        top_p=config.model.top_p,
        do_sample=config.model.do_sample,
        seed=seed + 2,
    )
    refutations: list[RefutationHandoff] = []
    refutation_errors: list[str | None] = []
    for analysis, generation in zip(analyses, second):
        parsed, error = parse_refutation(generation.text)
        if parsed is None:
            fallback = normalize_freeform_handoff(generation.text)
            parsed = RefutationHandoff(
                overall_assessment=fallback.tentative_verdict,
                decisions=[],
                new_claims=fallback.claims,
                unresolved_questions=["Structured refutation output failed schema validation"],
                summary=generation.text[:1500],
            )
        refutations.append(parsed)
        refutation_errors.append(error)
    third = backend.generate_batch(
        [
            final_adjudication_prompt(
                case,
                analysis.model_dump(mode="json"),
                refutation.model_dump(mode="json"),
                "structured-evidence multi-agent",
            )
            for case, analysis, refutation in zip(cases, analyses, refutations)
        ],
        max_new_tokens=config.budget.adjudication,
        temperature=config.model.temperature,
        top_p=config.model.top_p,
        do_sample=config.model.do_sample,
        seed=seed + 3,
    )
    records: list[ExperimentRecord] = []
    for case, analyst_generation, analysis, analysis_error, refuter_generation, refutation, refutation_error, final_generation in zip(
        cases,
        first,
        analyses,
        analysis_errors,
        second,
        refutations,
        refutation_errors,
        third,
    ):
        final_report, final_error = parse_final(final_generation.text)
        record = ExperimentRecord(
            run_id=_run_id("structured_mas", config, repetition, case.case_id),
            system="structured_mas",
            model=config.model.model_id,
            model_revision=config.model.revision,
            repetition=repetition,
            seed=seed,
            case=case,
            stages=[
                _stage("analyst", analyst_generation, analysis, analysis_error),
                _stage("refuter", refuter_generation, refutation, refutation_error),
                _stage("adjudication", final_generation, final_report, final_error),
            ],
            final_report=final_report,
            metadata={"protocol_hash": PROTOCOL_HASH},
        )
        records.append(_finalize(record))
    return records


SYSTEMS: dict[str, Callable[[list[CaseSample], ChatBackend, ExperimentConfig, int], list[ExperimentRecord]]] = {
    "self_refine": run_self_refine,
    "freeform_mas": run_freeform_mas,
    "structured_mas": run_structured_mas,
}


def run_experiments(config: ExperimentConfig) -> Path:
    pairs = load_pairs(config.prepared_pairs)
    pairs = [pair for index, pair in enumerate(pairs) if index % config.num_shards == config.shard_index]
    cases = [case for pair in pairs for case in pair_to_cases(pair)]
    output_dir = ensure_dir(config.output_dir)
    output_path = output_dir / f"records-shard-{config.shard_index:03d}-of-{config.num_shards:03d}.jsonl"
    if config.overwrite and output_path.exists():
        output_path.unlink()
    existing = {row.get("run_id") for row in read_jsonl(output_path)} if output_path.exists() else set()
    backend = create_backend(config.model)

    manifest = {
        "protocol_hash": PROTOCOL_HASH,
        "config": config.model_dump(mode="json"),
        "python": sys.version,
        "platform": platform.platform(),
        "pairs_in_shard": len(pairs),
        "cases_in_shard": len(cases),
    }
    (output_dir / f"run-manifest-shard-{config.shard_index:03d}.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8"
    )

    for repetition in range(config.repetitions):
        for system in config.systems:
            if system not in SYSTEMS:
                raise ValueError(f"Unsupported system: {system}")
            pending = [
                case
                for case in cases
                if _run_id(system, config, repetition, case.case_id) not in existing
            ]
            if not pending:
                print(f"Skipping completed {system}, repetition {repetition}")
                continue
            print(
                f"Running {system}, repetition {repetition}, "
                f"{len(pending)} code versions on {config.model.model_id}"
            )
            records = SYSTEMS[system](pending, backend, config, repetition)
            for record in tqdm(records, desc=f"saving {system}"):
                append_jsonl(output_path, record.model_dump(mode="json"))
                existing.add(record.run_id)
    return output_path



def _synthetic_generation(text: str) -> GenerationResult:
    """Represent an externally injected handoff as a zero-cost stage."""
    return GenerationResult(
        text=text,
        prompt_tokens=0,
        completion_tokens=0,
        latency_seconds=0.0,
    )


def run_rq3_self_refine_from_handoffs(
    cases: list[CaseSample],
    injected_handoffs: list[str],
    fault_types: list[str],
    backend: ChatBackend,
    config: ExperimentConfig,
    repetition: int = 0,
) -> list[ExperimentRecord]:
    if not (
        len(cases)
        == len(injected_handoffs)
        == len(fault_types)
    ):
        raise ValueError("RQ3 input lists must have equal lengths.")

    seed = config.base_seed + repetition * 1000 + 3000

    critiques = backend.generate_batch(
        [
            self_critique_prompt(case, handoff)
            for case, handoff in zip(cases, injected_handoffs)
        ],
        max_new_tokens=config.budget.critique,
        temperature=config.model.temperature,
        top_p=config.model.top_p,
        do_sample=config.model.do_sample,
        seed=seed + 1,
    )

    finals = backend.generate_batch(
        [
            final_adjudication_prompt(
                case,
                handoff,
                critique.text,
                "single-agent self-refinement with an injected upstream fault",
            )
            for case, handoff, critique in zip(
                cases,
                injected_handoffs,
                critiques,
            )
        ],
        max_new_tokens=config.budget.adjudication,
        temperature=config.model.temperature,
        top_p=config.model.top_p,
        do_sample=config.model.do_sample,
        seed=seed + 2,
    )

    records: list[ExperimentRecord] = []

    for case, handoff, fault_type, critique, final_generation in zip(
        cases,
        injected_handoffs,
        fault_types,
        critiques,
        finals,
    ):
        injected_generation = _synthetic_generation(handoff)

        injected_normalized = normalize_freeform_handoff(
            handoff,
            len(case.code.splitlines()),
        )

        critique_normalized = normalize_freeform_handoff(
            critique.text,
            len(case.code.splitlines()),
        )

        final_report, final_error = parse_final(
            final_generation.text
        )

        record = ExperimentRecord(
            run_id=stable_hash(
                PROTOCOL_HASH,
                "rq3",
                "self_refine",
                fault_type,
                case.case_id,
                repetition,
                length=40,
            ),
            system="self_refine",
            model=config.model.model_id,
            model_revision=config.model.revision,
            repetition=repetition,
            seed=seed,
            case=case,
            stages=[
                _stage(
                    "analysis_injected",
                    injected_generation,
                    injected_normalized,
                ),
                _stage(
                    "self_critique",
                    critique,
                    critique_normalized,
                ),
                _stage(
                    "adjudication",
                    final_generation,
                    final_report,
                    final_error,
                ),
            ],
            final_report=final_report,
            metadata={
                "protocol_hash": PROTOCOL_HASH,
                "experiment": "rq3_fault_injection",
                "fault_type": fault_type,
                "injected_stage": "analysis",
            },
        )

        records.append(_finalize(record))

    return records


def run_rq3_freeform_from_handoffs(
    cases: list[CaseSample],
    injected_handoffs: list[str],
    fault_types: list[str],
    backend: ChatBackend,
    config: ExperimentConfig,
    repetition: int = 0,
) -> list[ExperimentRecord]:
    if not (
        len(cases)
        == len(injected_handoffs)
        == len(fault_types)
    ):
        raise ValueError("RQ3 input lists must have equal lengths.")

    seed = config.base_seed + repetition * 1000 + 4000

    refutations = backend.generate_batch(
        [
            freeform_refutation_prompt(case, handoff)
            for case, handoff in zip(cases, injected_handoffs)
        ],
        max_new_tokens=config.budget.critique,
        temperature=config.model.temperature,
        top_p=config.model.top_p,
        do_sample=config.model.do_sample,
        seed=seed + 1,
    )

    finals = backend.generate_batch(
        [
            final_adjudication_prompt(
                case,
                handoff,
                refutation.text,
                "free-form multi-agent workflow with an injected upstream fault",
            )
            for case, handoff, refutation in zip(
                cases,
                injected_handoffs,
                refutations,
            )
        ],
        max_new_tokens=config.budget.adjudication,
        temperature=config.model.temperature,
        top_p=config.model.top_p,
        do_sample=config.model.do_sample,
        seed=seed + 2,
    )

    records: list[ExperimentRecord] = []

    for case, handoff, fault_type, refutation, final_generation in zip(
        cases,
        injected_handoffs,
        fault_types,
        refutations,
        finals,
    ):
        injected_generation = _synthetic_generation(handoff)

        injected_normalized = normalize_freeform_handoff(
            handoff,
            len(case.code.splitlines()),
        )

        refuter_normalized = normalize_freeform_handoff(
            refutation.text,
            len(case.code.splitlines()),
        )

        final_report, final_error = parse_final(
            final_generation.text
        )

        record = ExperimentRecord(
            run_id=stable_hash(
                PROTOCOL_HASH,
                "rq3",
                "freeform_mas",
                fault_type,
                case.case_id,
                repetition,
                length=40,
            ),
            system="freeform_mas",
            model=config.model.model_id,
            model_revision=config.model.revision,
            repetition=repetition,
            seed=seed,
            case=case,
            stages=[
                _stage(
                    "analyst_injected",
                    injected_generation,
                    injected_normalized,
                ),
                _stage(
                    "refuter",
                    refutation,
                    refuter_normalized,
                ),
                _stage(
                    "adjudication",
                    final_generation,
                    final_report,
                    final_error,
                ),
            ],
            final_report=final_report,
            metadata={
                "protocol_hash": PROTOCOL_HASH,
                "experiment": "rq3_fault_injection",
                "fault_type": fault_type,
                "injected_stage": "analyst",
            },
        )

        records.append(_finalize(record))

    return records


def run_rq3_structured_from_handoffs(
    cases: list[CaseSample],
    injected_handoffs: list[dict[str, Any]],
    fault_types: list[str],
    backend: ChatBackend,
    config: ExperimentConfig,
    repetition: int = 0,
) -> list[ExperimentRecord]:
    if not (
        len(cases)
        == len(injected_handoffs)
        == len(fault_types)
    ):
        raise ValueError("RQ3 input lists must have equal lengths.")

    seed = config.base_seed + repetition * 1000 + 5000

    validated_handoffs: list[AnalysisHandoff] = []

    for handoff in injected_handoffs:
        validated_handoffs.append(
            AnalysisHandoff.model_validate(handoff)
        )

    refutations = backend.generate_batch(
        [
            structured_refutation_prompt(case, handoff)
            for case, handoff in zip(
                cases,
                validated_handoffs,
            )
        ],
        max_new_tokens=config.budget.critique,
        temperature=config.model.temperature,
        top_p=config.model.top_p,
        do_sample=config.model.do_sample,
        seed=seed + 1,
    )

    parsed_refutations: list[RefutationHandoff] = []
    refutation_errors: list[str | None] = []

    for generation in refutations:
        parsed, error = parse_refutation(generation.text)

        if parsed is None:
            fallback = normalize_freeform_handoff(
                generation.text
            )

            parsed = RefutationHandoff(
                overall_assessment=(
                    fallback.tentative_verdict
                ),
                decisions=[],
                new_claims=[],
                unresolved_questions=[
                    "Structured refutation could not be parsed."
                ],
                summary=fallback.summary,
            )

        parsed_refutations.append(parsed)
        refutation_errors.append(error)

    finals = backend.generate_batch(
        [
            final_adjudication_prompt(
                case,
                analysis.model_dump(mode="json"),
                refutation.model_dump(mode="json"),
                "structured multi-agent workflow with an injected upstream fault",
            )
            for case, analysis, refutation in zip(
                cases,
                validated_handoffs,
                parsed_refutations,
            )
        ],
        max_new_tokens=config.budget.adjudication,
        temperature=config.model.temperature,
        top_p=config.model.top_p,
        do_sample=config.model.do_sample,
        seed=seed + 2,
    )

    records: list[ExperimentRecord] = []

    for (
        case,
        handoff,
        fault_type,
        refutation_generation,
        parsed_refutation,
        refutation_error,
        final_generation,
    ) in zip(
        cases,
        validated_handoffs,
        fault_types,
        refutations,
        parsed_refutations,
        refutation_errors,
        finals,
    ):
        handoff_json = json.dumps(
            handoff.model_dump(mode="json"),
            ensure_ascii=False,
        )

        injected_generation = _synthetic_generation(
            handoff_json
        )

        final_report, final_error = parse_final(
            final_generation.text
        )

        record = ExperimentRecord(
            run_id=stable_hash(
                PROTOCOL_HASH,
                "rq3",
                "structured_mas",
                fault_type,
                case.case_id,
                repetition,
                length=40,
            ),
            system="structured_mas",
            model=config.model.model_id,
            model_revision=config.model.revision,
            repetition=repetition,
            seed=seed,
            case=case,
            stages=[
                _stage(
                    "analyst_injected",
                    injected_generation,
                    handoff,
                ),
                _stage(
                    "refuter",
                    refutation_generation,
                    parsed_refutation,
                    refutation_error,
                ),
                _stage(
                    "adjudication",
                    final_generation,
                    final_report,
                    final_error,
                ),
            ],
            final_report=final_report,
            metadata={
                "protocol_hash": PROTOCOL_HASH,
                "experiment": "rq3_fault_injection",
                "fault_type": fault_type,
                "injected_stage": "analyst",
            },
        )

        records.append(_finalize(record))

    return records
