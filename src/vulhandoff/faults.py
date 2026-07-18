from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

from tqdm.auto import tqdm

import vulhandoff.parsing as parsing_module
import vulhandoff.prompts as prompts_module

from vulhandoff.config import FaultConfig
from vulhandoff.data import load_pairs, pair_to_cases
from vulhandoff.llm import create_backend
from vulhandoff.models import (
    CaseSample,
    EvidenceClaim,
    FaultExperimentRecord,
    FaultSpec,
    FinalReport,
    GenerationResult,
    GuardStatus,
    LineSpan,
    RefutationHandoff,
    StageRecord,
    Verdict,
)
from vulhandoff.parsing import normalize_freeform_handoff, parse_final, parse_refutation
from vulhandoff.prompts import (
    BASE_POLICY,
    fault_freeform_handoff,
    fault_structured_handoff,
    final_adjudication_prompt,
    freeform_refutation_prompt,
    structured_refutation_prompt,
)
from vulhandoff.utils import append_jsonl, ensure_dir, read_jsonl, stable_hash


COMMON_WRONG_CWES = ["CWE-78", "CWE-79", "CWE-89", "CWE-119", "CWE-190", "CWE-287", "CWE-416"]
FAULT_PROTOCOL_HASH = stable_hash(
    Path(__file__).read_text(encoding="utf-8"),
    Path(prompts_module.__file__).read_text(encoding="utf-8"),
    Path(parsing_module.__file__).read_text(encoding="utf-8"),
    length=16,
)


def _gold_span(case: CaseSample) -> list[LineSpan]:
    if case.gold_lines:
        return [LineSpan(start_line=min(case.gold_lines), end_line=max(case.gold_lines))]
    return [LineSpan(start_line=1, end_line=1)]


def _wrong_line(case: CaseSample) -> int | None:
    line_count = len(case.code.splitlines())
    gold = set(case.gold_lines)
    candidates = [line for line in range(1, line_count + 1) if line not in gold]
    if not candidates:
        return None
    anchor = min(gold) if gold else 1
    return max(candidates, key=lambda line: abs(line - anchor))


def make_fault(case: CaseSample, fault_type: str) -> FaultSpec | None:
    gold_verdict = Verdict.VULNERABLE if case.label == 1 else Verdict.NOT_VULNERABLE
    faulty_verdict = gold_verdict
    spans = _gold_span(case)
    cwes = list(case.cwe_ids[:1])
    guard = GuardStatus.UNKNOWN
    gold_value: Any = None
    faulty_value: Any = None
    statement = "The cited evidence supports a vulnerability-analysis conclusion."

    if fault_type == "label_flip":
        faulty_verdict = (
            Verdict.NOT_VULNERABLE if gold_verdict == Verdict.VULNERABLE else Verdict.VULNERABLE
        )
        gold_value = gold_verdict.value
        faulty_value = faulty_verdict.value
        if faulty_verdict == Verdict.VULNERABLE:
            statement = "The function contains an attacker-reachable vulnerability at the cited location."
        else:
            statement = "The function is not vulnerable because the relevant behavior is adequately constrained."
    elif fault_type == "wrong_cwe":
        if case.label != 1 or not case.cwe_ids:
            return None
        correct = case.cwe_ids[0]
        wrong = next((candidate for candidate in COMMON_WRONG_CWES if candidate != correct), "CWE-999")
        faulty_verdict = Verdict.VULNERABLE
        gold_value = correct
        faulty_value = wrong
        cwes = [wrong]
        statement = f"The cited vulnerable behavior is best classified as {wrong}."
    elif fault_type == "wrong_location":
        if case.label != 1 or not case.gold_lines:
            return None
        wrong = _wrong_line(case)
        if wrong is None:
            return None
        gold_value = sorted(case.gold_lines)
        faulty_value = wrong
        spans = [LineSpan(start_line=wrong, end_line=wrong)]
        faulty_verdict = Verdict.VULNERABLE
        statement = "The vulnerability is located at the cited line."
    elif fault_type == "false_guard":
        # This fault is intentionally not enabled in reference configs. Its semantic validity
        # must be manually confirmed for every selected case.
        if case.label == 1:
            faulty_verdict = Verdict.NOT_VULNERABLE
            guard = GuardStatus.PRESENT_EFFECTIVE
            gold_value = "known vulnerable version"
            faulty_value = "effective_guard_present"
            statement = "An effective guard blocks attacker-controlled input before the sensitive operation."
        else:
            faulty_verdict = Verdict.VULNERABLE
            guard = GuardStatus.ABSENT
            gold_value = "known fixed version"
            faulty_value = "guard_absent"
            statement = "The security guard is absent, leaving the operation exploitable."
    else:
        raise ValueError(f"Unknown fault type: {fault_type}")

    claim = EvidenceClaim(
        claim_id="INJECTED-C1",
        claim_type=f"injected_{fault_type}",
        statement=statement,
        spans=spans,
        cwes=cwes,
        guard_status=guard,
        confidence=0.95,
    )
    fault_id = stable_hash(case.case_id, fault_type, gold_value, faulty_value, length=32)
    return FaultSpec(
        fault_id=fault_id,
        case_id=case.case_id,
        pair_id=case.pair_id,
        fault_type=fault_type,
        gold_value=gold_value,
        faulty_value=faulty_value,
        claim=claim,
        faulty_verdict=faulty_verdict,
        metadata={"gold_verdict": gold_verdict.value},
    )


def make_faults(
    cases: Iterable[CaseSample], fault_types: list[str]
) -> list[tuple[CaseSample, FaultSpec]]:
    result: list[tuple[CaseSample, FaultSpec]] = []
    for case in cases:
        for fault_type in fault_types:
            fault = make_fault(case, fault_type)
            if fault is not None:
                result.append((case, fault))
    return result


def _predicted_lines(report: FinalReport) -> set[int]:
    return {
        line
        for finding in report.findings
        for span in finding.spans
        for line in span.lines()
    }


def _predicted_cwes(report: FinalReport) -> set[str]:
    return set(report.cwes) | {cwe for finding in report.findings for cwe in finding.cwes}


def classify_fault_outcome(
    case: CaseSample, fault: FaultSpec, report: FinalReport | None
) -> tuple[str, dict[str, Any]]:
    if report is None:
        return "parse_failure", {
            "verdict_correct": False,
            "fault_value_repeated": False,
            "gold_value_recovered": False,
        }
    gold_verdict = Verdict.VULNERABLE if case.label == 1 else Verdict.NOT_VULNERABLE
    verdict_correct = report.verdict == gold_verdict
    if report.verdict == Verdict.UNCERTAIN:
        return "contained", {
            "verdict_correct": False,
            "fault_value_repeated": False,
            "gold_value_recovered": False,
        }

    predicted_lines = _predicted_lines(report)
    predicted_cwes = _predicted_cwes(report)
    gold_lines = set(case.gold_lines)
    fault_repeated = False
    gold_recovered = False

    if fault.fault_type in {"label_flip", "false_guard"}:
        fault_repeated = report.verdict == fault.faulty_verdict and not verdict_correct
        gold_recovered = verdict_correct
    elif fault.fault_type == "wrong_cwe":
        fault_repeated = str(fault.faulty_value) in predicted_cwes
        gold_recovered = str(fault.gold_value) in predicted_cwes and not fault_repeated
    elif fault.fault_type == "wrong_location":
        faulty_line = int(fault.faulty_value)
        fault_repeated = faulty_line in predicted_lines and faulty_line not in gold_lines
        gold_recovered = bool(predicted_lines.intersection(gold_lines)) and not fault_repeated

    extra_unsupported = False
    if case.label == 0:
        extra_unsupported = len(report.findings) > 1
    elif predicted_lines and gold_lines:
        extra_unsupported = len(predicted_lines - gold_lines) > (1 if fault_repeated else 0)

    if fault_repeated:
        outcome = "amplified" if extra_unsupported else "propagated"
    elif gold_recovered and verdict_correct:
        outcome = "repaired"
    elif verdict_correct:
        outcome = "verdict_repaired_evidence_unresolved"
    else:
        outcome = "other_error"
    return outcome, {
        "verdict_correct": verdict_correct,
        "fault_value_repeated": fault_repeated,
        "gold_value_recovered": gold_recovered,
        "extra_unsupported_findings": extra_unsupported,
    }


def _stage(
    name: str,
    generation: GenerationResult,
    parsed: Any = None,
    error: str | None = None,
) -> StageRecord:
    if hasattr(parsed, "model_dump"):
        parsed = parsed.model_dump(mode="json")
    elif parsed is not None and not isinstance(parsed, dict):
        parsed = {"value": parsed}
    return StageRecord(
        stage=name,
        raw_text=generation.text,
        parsed=parsed,
        parse_error=error,
        prompt_tokens=generation.prompt_tokens,
        completion_tokens=generation.completion_tokens,
        latency_seconds=generation.latency_seconds,
    )


def _run_id(mode: str, config: FaultConfig, repetition: int, fault_id: str) -> str:
    return stable_hash(
        FAULT_PROTOCOL_HASH,
        mode,
        config.model.model_id,
        config.model.revision,
        config.budget.model_dump(mode="json"),
        config.model.temperature,
        config.model.do_sample,
        repetition,
        fault_id,
        length=40,
    )


def run_fault_experiments(config: FaultConfig) -> Path:
    if "false_guard" in config.fault_types:
        print(
            "WARNING: false_guard is enabled. Do not report it unless each case was manually "
            "validated as a semantically false guard claim."
        )
    pairs = load_pairs(config.prepared_pairs)
    pairs = [pair for index, pair in enumerate(pairs) if index % config.num_shards == config.shard_index]
    cases = [case for pair in pairs for case in pair_to_cases(pair)]
    case_faults = make_faults(cases, config.fault_types)
    output_dir = ensure_dir(config.output_dir)
    output_path = output_dir / (
        f"fault-records-shard-{config.shard_index:03d}-of-{config.num_shards:03d}.jsonl"
    )
    if config.overwrite and output_path.exists():
        output_path.unlink()
    existing = {row.get("run_id") for row in read_jsonl(output_path)} if output_path.exists() else set()
    backend = create_backend(config.model)
    manifest = {
        "protocol_hash": FAULT_PROTOCOL_HASH,
        "config": config.model_dump(mode="json"),
        "pairs_in_shard": len(pairs),
        "candidate_faults": len(case_faults),
    }
    (output_dir / f"fault-manifest-shard-{config.shard_index:03d}.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8"
    )

    for repetition in range(config.repetitions):
        for mode in config.handoff_modes:
            pending = [
                (case, fault)
                for case, fault in case_faults
                if _run_id(mode, config, repetition, fault.fault_id) not in existing
            ]
            if not pending:
                continue
            seed = config.base_seed + repetition * 1000 + (10 if mode == "freeform" else 20)
            if mode == "freeform":
                upstream = [fault_freeform_handoff(fault) for _, fault in pending]
                refutation_prompts = [
                    freeform_refutation_prompt(case, handoff)
                    for (case, _), handoff in zip(pending, upstream)
                ]
            elif mode == "structured":
                upstream = [fault_structured_handoff(fault) for _, fault in pending]
                refutation_prompts = [
                    structured_refutation_prompt(case, handoff)
                    for (case, _), handoff in zip(pending, upstream)
                ]
            else:
                raise ValueError(f"Unsupported handoff mode: {mode}")

            refutation_generations = backend.generate_batch(
                refutation_prompts,
                max_new_tokens=config.budget.critique,
                temperature=config.model.temperature,
                top_p=config.model.top_p,
                do_sample=config.model.do_sample,
                seed=seed + 1,
            )
            refutations: list[str | RefutationHandoff] = []
            refutation_errors: list[str | None] = []
            for (case, _), generation in zip(pending, refutation_generations):
                if mode == "structured":
                    parsed, error = parse_refutation(generation.text)
                    if parsed is None:
                        fallback = normalize_freeform_handoff(generation.text, len(case.code.splitlines()))
                        parsed = RefutationHandoff(
                            overall_assessment=fallback.tentative_verdict,
                            decisions=[],
                            new_claims=fallback.claims,
                            unresolved_questions=["Structured refutation failed schema validation"],
                            summary=generation.text[:1500],
                        )
                    refutations.append(parsed)
                    refutation_errors.append(error)
                else:
                    refutations.append(generation.text)
                    refutation_errors.append(None)

            adjudication_prompts = []
            for (case, _), upstream_value, refutation in zip(pending, upstream, refutations):
                refutation_value = (
                    refutation.model_dump(mode="json")
                    if hasattr(refutation, "model_dump")
                    else refutation
                )
                adjudication_prompts.append(
                    final_adjudication_prompt(
                        case,
                        upstream_value,
                        refutation_value,
                        f"fault-injected {mode}",
                    )
                )
            final_generations = backend.generate_batch(
                adjudication_prompts,
                max_new_tokens=config.budget.adjudication,
                temperature=config.model.temperature,
                top_p=config.model.top_p,
                do_sample=config.model.do_sample,
                seed=seed + 2,
            )

            iterator = zip(
                pending,
                upstream,
                refutation_generations,
                refutations,
                refutation_errors,
                final_generations,
            )
            for (case, fault), upstream_value, ref_gen, refutation, ref_error, final_gen in tqdm(
                iterator, total=len(pending), desc=f"saving fault {mode}"
            ):
                final_report, final_error = parse_final(final_gen.text)
                outcome, outcome_details = classify_fault_outcome(case, fault, final_report)
                upstream_text = (
                    upstream_value
                    if isinstance(upstream_value, str)
                    else json.dumps(upstream_value, ensure_ascii=False)
                )
                pseudo = GenerationResult(text=upstream_text)
                record = FaultExperimentRecord(
                    run_id=_run_id(mode, config, repetition, fault.fault_id),
                    handoff_mode=mode,
                    model=config.model.model_id,
                    model_revision=config.model.revision,
                    repetition=repetition,
                    seed=seed,
                    case=case,
                    fault=fault,
                    stages=[
                        _stage("injected_upstream", pseudo, upstream_value),
                        _stage("refuter", ref_gen, refutation, ref_error),
                        _stage("adjudication", final_gen, final_report, final_error),
                    ],
                    final_report=final_report,
                    total_prompt_tokens=ref_gen.prompt_tokens + final_gen.prompt_tokens,
                    total_completion_tokens=ref_gen.completion_tokens + final_gen.completion_tokens,
                    total_latency_seconds=ref_gen.latency_seconds + final_gen.latency_seconds,
                    outcome=outcome,
                    metadata={
                        "protocol_hash": FAULT_PROTOCOL_HASH,
                        **outcome_details,
                    },
                )
                append_jsonl(output_path, record.model_dump(mode="json"))
                existing.add(record.run_id)
    return output_path
