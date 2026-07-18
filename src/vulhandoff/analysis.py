from __future__ import annotations

import glob
import itertools
import json
import math
from pathlib import Path
from typing import Any, Iterable

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from scipy.stats import chi2, wilcoxon
from statsmodels.stats.contingency_tables import mcnemar
from statsmodels.stats.multitest import multipletests

from vulhandoff.config import AnalysisConfig
from vulhandoff.models import (
    AnalysisHandoff,
    ExperimentRecord,
    FaultExperimentRecord,
    FinalFinding,
    FinalReport,
    RefutationHandoff,
    Verdict,
)
from vulhandoff.utils import ensure_dir, read_jsonl


def _resolve_files(path_or_pattern: str | Path, prefix: str) -> list[Path]:
    value = Path(path_or_pattern)
    if value.is_file():
        return [value]
    if value.is_dir():
        files = sorted(value.glob(f"{prefix}*.jsonl"))
        return files or sorted(value.glob("*.jsonl"))
    resolved: list[Path] = []
    for item in sorted(glob.glob(str(path_or_pattern))):
        candidate = Path(item)
        if candidate.is_file():
            resolved.append(candidate)
        elif candidate.is_dir():
            files = sorted(candidate.glob(f"{prefix}*.jsonl"))
            resolved.extend(files or sorted(candidate.glob("*.jsonl")))
    return resolved


def load_experiment_records(path_or_pattern: str | Path) -> list[ExperimentRecord]:
    by_id: dict[str, ExperimentRecord] = {}
    for path in _resolve_files(path_or_pattern, "records-shard-"):
        for row in read_jsonl(path):
            record = ExperimentRecord.model_validate(row)
            by_id[record.run_id] = record
    return list(by_id.values())


def load_fault_records(path_or_pattern: str | Path | None) -> list[FaultExperimentRecord]:
    if not path_or_pattern:
        return []
    by_id: dict[str, FaultExperimentRecord] = {}
    for path in _resolve_files(path_or_pattern, "fault-records-"):
        for row in read_jsonl(path):
            record = FaultExperimentRecord.model_validate(row)
            by_id[record.run_id] = record
    return list(by_id.values())


def verdict_label(report: FinalReport | None) -> int | None:
    if report is None or report.verdict == Verdict.UNCERTAIN:
        return None
    return 1 if report.verdict == Verdict.VULNERABLE else 0


def report_lines(report: FinalReport | None) -> set[int]:
    if report is None:
        return set()
    return {
        line
        for finding in report.findings
        for span in finding.spans
        for line in span.lines()
    }


def report_cwes(report: FinalReport | None) -> set[str]:
    if report is None:
        return set()
    return set(report.cwes) | {cwe for finding in report.findings for cwe in finding.cwes}


def records_frame(records: Iterable[ExperimentRecord]) -> pd.DataFrame:
    rows: list[dict[str, Any]] = []
    for record in records:
        predicted = verdict_label(record.final_report)
        gold = record.case.label
        predicted_lines = report_lines(record.final_report)
        gold_lines = set(record.case.gold_lines)
        line_true_positive = len(predicted_lines.intersection(gold_lines))
        line_precision = (
            line_true_positive / len(predicted_lines) if predicted_lines else 0.0
        )
        line_recall = line_true_positive / len(gold_lines) if gold_lines else math.nan
        line_f1 = (
            2 * line_precision * line_recall / (line_precision + line_recall)
            if gold_lines and line_precision + line_recall > 0
            else 0.0 if gold_lines else math.nan
        )
        predicted_cwes = report_cwes(record.final_report)
        gold_cwes = set(record.case.cwe_ids)
        rows.append(
            {
                "run_id": record.run_id,
                "dataset": record.case.dataset,
                "model": record.model,
                "model_revision": record.model_revision,
                "system": record.system,
                "repetition": record.repetition,
                "case_id": record.case.case_id,
                "pair_id": record.case.pair_id,
                "project": record.case.project,
                "version": record.case.version,
                "gold_label": gold,
                "predicted_label": predicted,
                "abstained": predicted is None,
                "correct": predicted == gold,
                "parse_failed": record.parse_failed,
                "any_stage_parse_failed": bool(
                    record.metadata.get(
                        "any_stage_parse_failed",
                        any(stage.parse_error for stage in record.stages),
                    )
                ),
                "upstream_parse_failed": bool(
                    record.metadata.get(
                        "upstream_parse_failed",
                        any(
                            stage.parse_error
                            for stage in record.stages
                            if stage.stage != "adjudication"
                        ),
                    )
                ),
                "gold_lines": sorted(gold_lines),
                "predicted_lines": sorted(predicted_lines),
                "localization_hit": bool(predicted_lines.intersection(gold_lines)) if gold == 1 and gold_lines else math.nan,
                "line_precision": line_precision if gold == 1 else math.nan,
                "line_recall": line_recall if gold == 1 else math.nan,
                "line_f1": line_f1 if gold == 1 else math.nan,
                "gold_cwes": sorted(gold_cwes),
                "predicted_cwes": sorted(predicted_cwes),
                "cwe_any_match": bool(gold_cwes.intersection(predicted_cwes)) if gold == 1 and gold_cwes else math.nan,
                "prompt_tokens": record.total_prompt_tokens,
                "completion_tokens": record.total_completion_tokens,
                "total_tokens": record.total_prompt_tokens + record.total_completion_tokens,
                "latency_seconds": record.total_latency_seconds,
                "num_findings": len(record.final_report.findings) if record.final_report else 0,
            }
        )
    return pd.DataFrame(rows)


def end_task_metrics(frame: pd.DataFrame) -> pd.DataFrame:
    rows: list[dict[str, Any]] = []
    groups = ["dataset", "model", "model_revision", "system", "repetition"]
    for keys, group in frame.groupby(groups, dropna=False):
        dataset, model, revision, system, repetition = keys
        positives = group[group.gold_label == 1]
        negatives = group[group.gold_label == 0]
        true_positive = int(((group.gold_label == 1) & (group.predicted_label == 1)).sum())
        false_positive = int(((group.gold_label == 0) & (group.predicted_label == 1)).sum())
        true_negative = int(((group.gold_label == 0) & (group.predicted_label == 0)).sum())
        false_negative_or_abstain = len(positives) - true_positive
        vulnerable_recall = true_positive / len(positives) if len(positives) else math.nan
        fixed_tnr = true_negative / len(negatives) if len(negatives) else math.nan
        precision = true_positive / (true_positive + false_positive) if true_positive + false_positive else 0.0
        f1 = (
            2 * precision * vulnerable_recall / (precision + vulnerable_recall)
            if precision + vulnerable_recall > 0
            else 0.0
        )
        non_abstained = group[~group.abstained]
        rows.append(
            {
                "dataset": dataset,
                "model": model,
                "model_revision": revision,
                "system": system,
                "repetition": repetition,
                "n_versions": len(group),
                "accuracy_abstention_as_error": float(group.correct.mean()),
                "balanced_accuracy_abstention_as_error": float(np.nanmean([vulnerable_recall, fixed_tnr])),
                "vulnerable_precision": precision,
                "vulnerable_recall": vulnerable_recall,
                "vulnerable_f1": f1,
                "fixed_false_positive_rate": false_positive / len(negatives) if len(negatives) else math.nan,
                "fixed_true_negative_rate": fixed_tnr,
                "coverage": 1.0 - float(group.abstained.mean()),
                "selective_accuracy": float(non_abstained.correct.mean()) if len(non_abstained) else math.nan,
                "abstention_rate": float(group.abstained.mean()),
                "parse_failure_rate": float(group.parse_failed.mean()),
                "any_stage_parse_failure_rate": float(
                    group.any_stage_parse_failed.mean()
                ),
                "upstream_parse_failure_rate": float(
                    group.upstream_parse_failed.mean()
                ),
                "localization_hit_rate": float(positives.localization_hit.dropna().mean()) if positives.localization_hit.notna().any() else math.nan,
                "mean_patch_line_f1": float(positives.line_f1.dropna().mean()) if positives.line_f1.notna().any() else math.nan,
                "cwe_any_match_rate": float(positives.cwe_any_match.dropna().mean()) if positives.cwe_any_match.notna().any() else math.nan,
                "mean_total_tokens_per_version": float(group.total_tokens.mean()),
                "median_latency_seconds_per_version": float(group.latency_seconds.median()),
                "tp": true_positive,
                "fp": false_positive,
                "tn": true_negative,
                "fn_or_abstain": false_negative_or_abstain,
            }
        )
    return pd.DataFrame(rows)


def pair_metrics(frame: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    detail_rows: list[dict[str, Any]] = []
    keys = ["dataset", "model", "model_revision", "system", "repetition", "pair_id"]
    for values, group in frame.groupby(keys, dropna=False):
        dataset, model, revision, system, repetition, pair_id = values
        version_map = {row.version: row for row in group.itertuples()}
        vulnerable = version_map.get("vulnerable")
        fixed = version_map.get("fixed")
        if vulnerable is None or fixed is None:
            continue
        vulnerable_prediction = vulnerable.predicted_label
        fixed_prediction = fixed.predicted_label
        if pd.isna(vulnerable_prediction) or pd.isna(fixed_prediction):
            category = "abstained"
            correct = False
        elif vulnerable_prediction == 1 and fixed_prediction == 0:
            category = "pair_correct"
            correct = True
        elif vulnerable_prediction == 1 and fixed_prediction == 1:
            category = "both_vulnerable"
            correct = False
        elif vulnerable_prediction == 0 and fixed_prediction == 0:
            category = "both_not_vulnerable"
            correct = False
        else:
            category = "reversed"
            correct = False
        detail_rows.append(
            {
                "dataset": dataset,
                "model": model,
                "model_revision": revision,
                "system": system,
                "repetition": repetition,
                "pair_id": pair_id,
                "project": vulnerable.project,
                "pair_correct": correct,
                "pair_category": category,
                "vulnerable_correct": vulnerable_prediction == 1,
                "fixed_correct": fixed_prediction == 0,
                "total_tokens_pair": vulnerable.total_tokens + fixed.total_tokens,
                "latency_pair": vulnerable.latency_seconds + fixed.latency_seconds,
            }
        )
    detail = pd.DataFrame(detail_rows)
    if detail.empty:
        return detail, detail
    group_columns = ["dataset", "model", "model_revision", "system", "repetition"]
    summary = (
        detail.groupby(group_columns, dropna=False)
        .agg(
            n_pairs=("pair_id", "count"),
            pair_correct_rate=("pair_correct", "mean"),
            vulnerable_correct_rate=("vulnerable_correct", "mean"),
            fixed_correct_rate=("fixed_correct", "mean"),
            mean_tokens_per_pair=("total_tokens_pair", "mean"),
            median_latency_per_pair=("latency_pair", "median"),
        )
        .reset_index()
    )
    categories = (
        detail.pivot_table(
            index=group_columns,
            columns="pair_category",
            values="pair_id",
            aggfunc="count",
            fill_value=0,
        )
        .reset_index()
    )
    return detail, summary.merge(categories, on=group_columns, how="left")


def bootstrap_pair_correctness(
    detail: pd.DataFrame, iterations: int, seed: int
) -> pd.DataFrame:
    rows: list[dict[str, Any]] = []
    groups = ["dataset", "model", "model_revision", "system", "repetition"]
    rng = np.random.default_rng(seed)
    for keys, group in detail.groupby(groups, dropna=False):
        values = group.pair_correct.astype(float).to_numpy()
        if len(values) == 0:
            continue
        cluster_series = group.project.fillna(group.pair_id).astype(str)
        clusters = cluster_series.unique().tolist()
        cluster_values = {
            cluster: group.loc[cluster_series == cluster, "pair_correct"].astype(float).to_numpy()
            for cluster in clusters
        }
        estimates = np.empty(iterations)
        for index in range(iterations):
            sampled_clusters = rng.choice(clusters, size=len(clusters), replace=True)
            sampled_values = np.concatenate([cluster_values[cluster] for cluster in sampled_clusters])
            estimates[index] = sampled_values.mean()
        row = dict(zip(groups, keys))
        row.update(
            n_pairs=len(values),
            n_project_clusters=len(clusters),
            pair_correct_rate=float(values.mean()),
            ci_low=float(np.quantile(estimates, 0.025)),
            ci_high=float(np.quantile(estimates, 0.975)),
        )
        rows.append(row)
    return pd.DataFrame(rows)


def cochran_q(detail: pd.DataFrame) -> pd.DataFrame:
    rows: list[dict[str, Any]] = []
    for keys, group in detail.groupby(["dataset", "model", "model_revision", "repetition"], dropna=False):
        dataset, model, revision, repetition = keys
        matrix = group.pivot_table(index="pair_id", columns="system", values="pair_correct", aggfunc="first").dropna()
        if matrix.shape[1] < 3 or matrix.empty:
            continue
        values = matrix.astype(int).to_numpy()
        n, k = values.shape
        columns = values.sum(axis=0)
        row_sums = values.sum(axis=1)
        numerator = (k - 1) * (k * np.sum(columns**2) - np.sum(columns) ** 2)
        denominator = k * np.sum(row_sums) - np.sum(row_sums**2)
        statistic = numerator / denominator if denominator else math.nan
        p_value = 1 - chi2.cdf(statistic, k - 1) if not math.isnan(statistic) else math.nan
        rows.append(
            {
                "dataset": dataset,
                "model": model,
                "model_revision": revision,
                "repetition": repetition,
                "systems": ",".join(matrix.columns),
                "n_pairs": n,
                "q_statistic": statistic,
                "df": k - 1,
                "p_value": p_value,
            }
        )
    return pd.DataFrame(rows)


def mcnemar_pairwise(detail: pd.DataFrame) -> pd.DataFrame:
    rows: list[dict[str, Any]] = []
    for keys, group in detail.groupby(["dataset", "model", "model_revision", "repetition"], dropna=False):
        dataset, model, revision, repetition = keys
        matrix = group.pivot_table(index="pair_id", columns="system", values="pair_correct", aggfunc="first")
        local: list[dict[str, Any]] = []
        for left, right in itertools.combinations(sorted(matrix.columns), 2):
            paired = matrix[[left, right]].dropna().astype(bool)
            a_wrong_b_correct = int(((~paired[left]) & paired[right]).sum())
            a_correct_b_wrong = int((paired[left] & (~paired[right])).sum())
            result = mcnemar(
                [[0, a_wrong_b_correct], [a_correct_b_wrong, 0]],
                exact=a_wrong_b_correct + a_correct_b_wrong < 25,
                correction=True,
            )
            local.append(
                {
                    "dataset": dataset,
                    "model": model,
                    "model_revision": revision,
                    "repetition": repetition,
                    "system_a": left,
                    "system_b": right,
                    "n_pairs": len(paired),
                    "a_wrong_b_correct": a_wrong_b_correct,
                    "a_correct_b_wrong": a_correct_b_wrong,
                    "p_value": float(result.pvalue),
                }
            )
        if local:
            adjusted = multipletests([row["p_value"] for row in local], method="holm")[1]
            for row, p_holm in zip(local, adjusted):
                row["p_holm"] = float(p_holm)
                rows.append(row)
    return pd.DataFrame(rows)


def paired_wilcoxon(detail: pd.DataFrame, value_column: str) -> pd.DataFrame:
    rows: list[dict[str, Any]] = []
    for keys, group in detail.groupby(["dataset", "model", "model_revision", "repetition"], dropna=False):
        dataset, model, revision, repetition = keys
        matrix = group.pivot_table(index="pair_id", columns="system", values=value_column, aggfunc="first")
        local: list[dict[str, Any]] = []
        for left, right in itertools.combinations(sorted(matrix.columns), 2):
            paired = matrix[[left, right]].dropna()
            if len(paired) < 2 or np.allclose(paired[left], paired[right]):
                statistic, p_value = 0.0, 1.0
            else:
                statistic, p_value = wilcoxon(paired[left], paired[right], zero_method="wilcox")
            local.append(
                {
                    "dataset": dataset,
                    "model": model,
                    "model_revision": revision,
                    "repetition": repetition,
                    "metric": value_column,
                    "system_a": left,
                    "system_b": right,
                    "n_pairs": len(paired),
                    "statistic": float(statistic),
                    "p_value": float(p_value),
                }
            )
        if local:
            adjusted = multipletests([row["p_value"] for row in local], method="holm")[1]
            for row, p_holm in zip(local, adjusted):
                row["p_holm"] = float(p_holm)
                rows.append(row)
    return pd.DataFrame(rows)


def _claim_lines(claim: Any) -> set[int]:
    return {line for span in getattr(claim, "spans", []) for line in span.lines()}


def _claim_cwes(claim: Any) -> set[str]:
    return set(getattr(claim, "cwes", []) or [])


def _claim_supported(claim: Any, gold_lines: set[int], gold_cwes: set[str]) -> bool:
    return bool((_claim_lines(claim) & gold_lines) or (_claim_cwes(claim) & gold_cwes))


def _claim_matches_finding(claim: Any, finding: FinalFinding) -> bool:
    finding_lines = {line for span in finding.spans for line in span.lines()}
    if getattr(claim, "claim_id", None) in finding.source_claim_ids:
        return True
    if _claim_lines(claim) and _claim_lines(claim).intersection(finding_lines):
        return True
    if _claim_cwes(claim) and _claim_cwes(claim).intersection(finding.cwes):
        return True
    return False


def _refuter_claims(record: ExperimentRecord, analyst: AnalysisHandoff) -> tuple[list[Any], set[str]]:
    if len(record.stages) < 2 or not record.stages[1].parsed:
        return [], set()
    payload = record.stages[1].parsed
    try:
        if record.system == "structured_mas":
            refutation = RefutationHandoff.model_validate(payload)
            analyst_by_id = {claim.claim_id: claim for claim in analyst.claims}
            claims: list[Any] = list(refutation.new_claims)
            explicitly_refuted: set[str] = set()
            for decision in refutation.decisions:
                if decision.status == "refuted":
                    explicitly_refuted.add(decision.claim_id)
                elif decision.status == "corrected" and decision.corrected_claim is not None:
                    claims.append(decision.corrected_claim)
                elif decision.status == "supported" and decision.claim_id in analyst_by_id:
                    claims.append(analyst_by_id[decision.claim_id])
            return claims, explicitly_refuted
        normalized = AnalysisHandoff.model_validate(payload)
        return list(normalized.claims), set()
    except Exception:
        return [], set()


def patch_proxy_handoff_metrics(records: Iterable[ExperimentRecord]) -> pd.DataFrame:
    """Automatic RQ2 proxy metrics for vulnerable versions only.

    These measures use patch-line/CWE overlap and must not be presented as semantic ground truth.
    The manual blinded annotation is the primary evidence-quality analysis.
    """
    rows: list[dict[str, Any]] = []
    for record in records:
        if record.case.label != 1 or not record.stages or not record.stages[0].parsed:
            continue
        try:
            analyst = AnalysisHandoff.model_validate(record.stages[0].parsed)
        except Exception:
            continue
        gold_lines = set(record.case.gold_lines)
        gold_cwes = set(record.case.cwe_ids)
        supported = [claim for claim in analyst.claims if _claim_supported(claim, gold_lines, gold_cwes)]
        unsupported = [claim for claim in analyst.claims if claim not in supported]
        refuter_claims, explicitly_refuted = _refuter_claims(record, analyst)
        final_findings = record.final_report.findings if record.final_report else []
        retained_refuter = sum(
            any(
                (_claim_lines(claim) & _claim_lines(candidate))
                or (_claim_cwes(claim) & _claim_cwes(candidate))
                or claim.claim_id == getattr(candidate, "claim_id", None)
                for candidate in refuter_claims
            )
            for claim in supported
        )
        retained_final = sum(
            any(_claim_matches_finding(claim, finding) for finding in final_findings)
            for claim in supported
        )
        unsupported_final = sum(
            not (
                ({line for span in finding.spans for line in span.lines()} & gold_lines)
                or (set(finding.cwes) & gold_cwes)
            )
            for finding in final_findings
        )
        final_correct = verdict_label(record.final_report) == 1
        rows.append(
            {
                "dataset": record.case.dataset,
                "model": record.model,
                "model_revision": record.model_revision,
                "system": record.system,
                "repetition": record.repetition,
                "case_id": record.case.case_id,
                "pair_id": record.case.pair_id,
                "analyst_claims": len(analyst.claims),
                "patch_proxy_supported_analyst_claims": len(supported),
                "patch_proxy_unsupported_analyst_claims": len(unsupported),
                "supported_retained_to_refuter": retained_refuter,
                "supported_retained_to_final": retained_final,
                "refuter_retention_rate": retained_refuter / len(supported) if supported else math.nan,
                "final_retention_rate": retained_final / len(supported) if supported else math.nan,
                "explicit_refutation_rate": (
                    len(explicitly_refuted.intersection({claim.claim_id for claim in unsupported})) / len(unsupported)
                    if unsupported and record.system == "structured_mas"
                    else math.nan
                ),
                "unsupported_final_findings": unsupported_final,
                "unsupported_final_finding_rate": unsupported_final / len(final_findings) if final_findings else 0.0,
                "harm_event_proxy": int(bool(supported) and retained_final == 0 and not final_correct),
                "final_correct": final_correct,
            }
        )
    return pd.DataFrame(rows)


def patch_proxy_summary(frame: pd.DataFrame) -> pd.DataFrame:
    if frame.empty:
        return frame
    return (
        frame.groupby(["dataset", "model", "model_revision", "system", "repetition"], dropna=False)
        .agg(
            n_vulnerable_cases=("case_id", "count"),
            mean_analyst_claims=("analyst_claims", "mean"),
            refuter_retention_rate=("refuter_retention_rate", "mean"),
            final_retention_rate=("final_retention_rate", "mean"),
            explicit_refutation_rate=("explicit_refutation_rate", "mean"),
            unsupported_final_finding_rate=("unsupported_final_finding_rate", "mean"),
            harm_rate_proxy=("harm_event_proxy", "mean"),
        )
        .reset_index()
    )


def fault_frame(records: Iterable[FaultExperimentRecord]) -> pd.DataFrame:
    rows: list[dict[str, Any]] = []
    for record in records:
        rows.append(
            {
                "run_id": record.run_id,
                "dataset": record.case.dataset,
                "model": record.model,
                "model_revision": record.model_revision,
                "handoff_mode": record.handoff_mode,
                "repetition": record.repetition,
                "fault_id": record.fault.fault_id,
                "fault_type": record.fault.fault_type,
                "case_id": record.case.case_id,
                "pair_id": record.case.pair_id,
                "version": record.case.version,
                "outcome": record.outcome,
                "fault_propagated": record.outcome in {"propagated", "amplified"},
                "repaired": record.outcome == "repaired",
                "contained": record.outcome == "contained",
                "verdict_repaired_evidence_unresolved": record.outcome == "verdict_repaired_evidence_unresolved",
                "parse_failure": record.outcome == "parse_failure",
                "total_tokens": record.total_prompt_tokens + record.total_completion_tokens,
                "latency_seconds": record.total_latency_seconds,
            }
        )
    return pd.DataFrame(rows)


def fault_summary(frame: pd.DataFrame) -> pd.DataFrame:
    if frame.empty:
        return frame
    return (
        frame.groupby(["dataset", "model", "model_revision", "handoff_mode", "fault_type", "repetition"], dropna=False)
        .agg(
            n_faults=("fault_id", "count"),
            propagation_rate=("fault_propagated", "mean"),
            repair_rate=("repaired", "mean"),
            containment_rate=("contained", "mean"),
            verdict_repaired_evidence_unresolved_rate=("verdict_repaired_evidence_unresolved", "mean"),
            parse_failure_rate=("parse_failure", "mean"),
            mean_total_tokens=("total_tokens", "mean"),
            median_latency_seconds=("latency_seconds", "median"),
        )
        .reset_index()
    )


def fault_mcnemar(frame: pd.DataFrame) -> pd.DataFrame:
    rows: list[dict[str, Any]] = []
    for keys, group in frame.groupby(["dataset", "model", "model_revision", "fault_type", "repetition"], dropna=False):
        dataset, model, revision, fault_type, repetition = keys
        matrix = group.pivot_table(index="fault_id", columns="handoff_mode", values="fault_propagated", aggfunc="first")
        if not {"freeform", "structured"}.issubset(matrix.columns):
            continue
        paired = matrix[["freeform", "structured"]].dropna().astype(bool)
        free_only = int((paired.freeform & ~paired.structured).sum())
        structured_only = int((~paired.freeform & paired.structured).sum())
        result = mcnemar(
            [[0, free_only], [structured_only, 0]],
            exact=free_only + structured_only < 25,
            correction=True,
        )
        rows.append(
            {
                "dataset": dataset,
                "model": model,
                "model_revision": revision,
                "fault_type": fault_type,
                "repetition": repetition,
                "n_paired_faults": len(paired),
                "freeform_only_propagated": free_only,
                "structured_only_propagated": structured_only,
                "p_value": float(result.pvalue),
            }
        )
    if rows:
        adjusted = multipletests([row["p_value"] for row in rows], method="holm")[1]
        for row, p_holm in zip(rows, adjusted):
            row["p_holm"] = float(p_holm)
    return pd.DataFrame(rows)


def stability_summary(frame: pd.DataFrame) -> pd.DataFrame:
    if frame.empty or frame.repetition.nunique() < 2:
        return pd.DataFrame()
    rows: list[dict[str, Any]] = []
    for keys, group in frame.groupby(["dataset", "model", "model_revision", "system"], dropna=False):
        dataset, model, revision, system = keys
        stability_group = group.copy()
        stability_group["predicted_for_agreement"] = stability_group.predicted_label.fillna(-1).astype(int)
        case_pivot = stability_group.pivot_table(
            index="case_id",
            columns="repetition",
            values="predicted_for_agreement",
            aggfunc="first",
            dropna=False,
        )
        agreements = []
        for _, row in case_pivot.iterrows():
            values = [int(value) for value in row.tolist() if not pd.isna(value)]
            agreements.append(float(len(set(values)) <= 1) if values else 0.0)
        pair_detail, _ = pair_metrics(group)
        repetition_scores = pair_detail.groupby("repetition").pair_correct.mean()
        rows.append(
            {
                "dataset": dataset,
                "model": model,
                "model_revision": revision,
                "system": system,
                "repetitions": group.repetition.nunique(),
                "case_verdict_exact_agreement_rate": float(np.mean(agreements)) if agreements else math.nan,
                "mean_pair_correct_rate": float(repetition_scores.mean()),
                "sd_pair_correct_rate": float(repetition_scores.std(ddof=1)) if len(repetition_scores) > 1 else 0.0,
                "min_pair_correct_rate": float(repetition_scores.min()),
                "max_pair_correct_rate": float(repetition_scores.max()),
            }
        )
    return pd.DataFrame(rows)


def _write_table(frame: pd.DataFrame, stem: Path) -> Path:
    csv_path = stem.with_suffix(".csv")
    tex_path = stem.with_suffix(".tex")
    frame.to_csv(csv_path, index=False)
    try:
        tex_path.write_text(
            frame.to_latex(index=False, float_format=lambda value: f"{value:.3f}"),
            encoding="utf-8",
        )
    except Exception as exc:
        tex_path.write_text(f"% LaTeX export failed: {exc}\n", encoding="utf-8")
    return csv_path


def _label_column(frame: pd.DataFrame) -> pd.Series:
    if frame.model.nunique() > 1:
        return frame.model.str.split("/").str[-1] + " | " + frame.system
    return frame.system


def plot_pair_correctness(frame: pd.DataFrame, path: Path) -> None:
    if frame.empty:
        return
    plot = frame.copy()
    plot["label"] = _label_column(plot)
    plot = plot.groupby("label", as_index=False).agg(
        mean=("pair_correct_rate", "mean"),
        low=("ci_low", "mean"),
        high=("ci_high", "mean"),
    )
    x = np.arange(len(plot))
    yerr = np.vstack([plot["mean"] - plot["low"], plot["high"] - plot["mean"]])
    figure, axis = plt.subplots(figsize=(max(7, len(plot) * 0.9), 4.8))
    axis.bar(x, plot["mean"], yerr=yerr, capsize=4)
    axis.set_xticks(x, plot.label, rotation=25, ha="right")
    axis.set_ylim(0, 1)
    axis.set_ylabel("Pair-correct rate")
    axis.set_title("Vulnerable/fixed pair correctness")
    figure.tight_layout()
    figure.savefig(path, dpi=220)
    plt.close(figure)


def plot_cost_quality(detail: pd.DataFrame, path: Path) -> None:
    if detail.empty:
        return
    plot = detail.groupby(["model", "system"], as_index=False).agg(
        pair_correct=("pair_correct", "mean"),
        total_tokens_pair=("total_tokens_pair", "mean"),
    )
    plot["label"] = _label_column(plot)
    figure, axis = plt.subplots(figsize=(7.2, 4.8))
    axis.scatter(plot.total_tokens_pair, plot.pair_correct, s=70)
    for row in plot.itertuples():
        axis.annotate(row.label, (row.total_tokens_pair, row.pair_correct), xytext=(4, 4), textcoords="offset points")
    axis.set_xlabel("Mean tokens per vulnerable/fixed pair")
    axis.set_ylabel("Pair-correct rate")
    axis.set_ylim(0, 1)
    axis.set_title("Accuracy-cost trade-off")
    figure.tight_layout()
    figure.savefig(path, dpi=220)
    plt.close(figure)


def plot_handoff(frame: pd.DataFrame, path: Path) -> None:
    if frame.empty:
        return
    metrics = [
        "refuter_retention_rate",
        "final_retention_rate",
        "unsupported_final_finding_rate",
        "harm_rate_proxy",
    ]
    plot = frame.groupby(["model", "system"], as_index=False)[metrics].mean()
    plot["label"] = _label_column(plot)
    x = np.arange(len(plot))
    width = 0.19
    figure, axis = plt.subplots(figsize=(max(8, len(plot) * 1.0), 4.9))
    for index, metric in enumerate(metrics):
        axis.bar(x + (index - 1.5) * width, plot[metric], width=width, label=metric.replace("_", " "))
    axis.set_xticks(x, plot.label, rotation=25, ha="right")
    axis.set_ylim(0, 1)
    axis.set_ylabel("Patch-proxy rate")
    axis.set_title("Automatic evidence-handoff proxies")
    axis.legend(fontsize=8)
    figure.tight_layout()
    figure.savefig(path, dpi=220)
    plt.close(figure)


def plot_fault_outcomes(frame: pd.DataFrame, path: Path) -> None:
    if frame.empty:
        return
    counts = frame.groupby(["model", "handoff_mode", "outcome"]).size().rename("count").reset_index()
    counts["label"] = (
        counts.model.str.split("/").str[-1] + " | " + counts.handoff_mode
        if counts.model.nunique() > 1
        else counts.handoff_mode
    )
    pivot = counts.pivot_table(index="label", columns="outcome", values="count", aggfunc="sum", fill_value=0)
    pivot = pivot.div(pivot.sum(axis=1), axis=0)
    figure, axis = plt.subplots(figsize=(8.5, 4.9))
    bottom = np.zeros(len(pivot))
    for outcome in pivot.columns:
        values = pivot[outcome].to_numpy()
        axis.bar(pivot.index, values, bottom=bottom, label=outcome)
        bottom += values
    axis.set_ylim(0, 1)
    axis.set_ylabel("Proportion")
    axis.set_title("Controlled-fault outcomes")
    axis.legend(fontsize=8, bbox_to_anchor=(1.02, 1), loc="upper left")
    figure.tight_layout()
    figure.savefig(path, dpi=220)
    plt.close(figure)


def generate_all_results(config: AnalysisConfig) -> dict[str, Path]:
    output = ensure_dir(config.output_dir)
    tables = ensure_dir(output / "tables")
    figures = ensure_dir(output / "figures")
    records = load_experiment_records(config.main_results)
    if not records:
        raise ValueError(f"No experiment records found at {config.main_results}")
    cases = records_frame(records)
    end_metrics = end_task_metrics(cases)
    pair_detail, pair_summary_frame = pair_metrics(cases)
    pair_ci = bootstrap_pair_correctness(pair_detail, config.bootstrap_iterations, config.seed)
    q_tests = cochran_q(pair_detail)
    mc_tests = mcnemar_pairwise(pair_detail)
    token_tests = paired_wilcoxon(pair_detail, "total_tokens_pair")
    latency_tests = paired_wilcoxon(pair_detail, "latency_pair")
    handoff_cases = patch_proxy_handoff_metrics(records)
    handoff_summary_frame = patch_proxy_summary(handoff_cases)
    stability = stability_summary(cases)

    tables_to_write = {
        "case_level_results": cases,
        "rq1_end_task_metrics": end_metrics,
        "rq1_pair_detail": pair_detail,
        "rq1_pair_metrics": pair_summary_frame,
        "rq1_pair_bootstrap_ci": pair_ci,
        "rq1_cochran_q": q_tests,
        "rq1_mcnemar_pairwise": mc_tests,
        "efficiency_tokens_wilcoxon": token_tests,
        "efficiency_latency_wilcoxon": latency_tests,
        "rq2_patch_proxy_case_metrics": handoff_cases,
        "rq2_patch_proxy_summary": handoff_summary_frame,
        "stability_summary": stability,
    }
    paths: dict[str, Path] = {
        name: _write_table(frame, tables / name) for name, frame in tables_to_write.items()
    }

    fault_records = load_fault_records(config.fault_results)
    faults = fault_frame(fault_records)
    if not faults.empty:
        fault_summary_frame = fault_summary(faults)
        fault_tests = fault_mcnemar(faults)
        paths["rq3_fault_rows"] = _write_table(faults, tables / "rq3_fault_rows")
        paths["rq3_fault_summary"] = _write_table(fault_summary_frame, tables / "rq3_fault_summary")
        paths["rq3_fault_mcnemar"] = _write_table(fault_tests, tables / "rq3_fault_mcnemar")
        plot_fault_outcomes(faults, figures / "rq3_fault_outcomes.png")
        paths["rq3_fault_outcomes_figure"] = figures / "rq3_fault_outcomes.png"

    plot_pair_correctness(pair_ci, figures / "rq1_pair_correctness.png")
    plot_cost_quality(pair_detail, figures / "rq1_cost_quality.png")
    plot_handoff(handoff_summary_frame, figures / "rq2_patch_proxy_handoffs.png")
    paths["rq1_pair_correctness_figure"] = figures / "rq1_pair_correctness.png"
    paths["rq1_cost_quality_figure"] = figures / "rq1_cost_quality.png"
    paths["rq2_patch_proxy_figure"] = figures / "rq2_patch_proxy_handoffs.png"

    manifest = {
        "records": len(records),
        "fault_records": len(fault_records),
        "models": sorted(cases.model.unique().tolist()),
        "systems": sorted(cases.system.unique().tolist()),
        "datasets": sorted(cases.dataset.unique().tolist()),
        "results": {name: str(path) for name, path in paths.items()},
        "warning": (
            "RQ2 patch-proxy metrics are not semantic ground truth. Use the independent "
            "human annotation workflow for claims about evidence distortion or repair."
        ),
    }
    manifest_path = output / "result_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    paths["manifest"] = manifest_path
    return paths
