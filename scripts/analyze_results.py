from __future__ import annotations

import argparse
import json
import math
from itertools import combinations
from pathlib import Path

import numpy as np
import pandas as pd
from scipy.stats import binomtest, wilcoxon
from statsmodels.stats.contingency_tables import cochrans_q
from statsmodels.stats.proportion import proportion_confint


def norm(value):
    if value is None:
        return None
    text = str(value).strip().lower()
    if text in {"vulnerable", "true", "1", "yes", "positive"}:
        return "vulnerable"
    if text in {
        "fixed",
        "not_vulnerable",
        "not vulnerable",
        "non_vulnerable",
        "non-vulnerable",
        "false",
        "0",
        "no",
        "negative",
        "safe",
    }:
        return "fixed"
    if text in {"uncertain", "none", "nan"}:
        return "uncertain"
    return text


def wilson(k: int, n: int) -> tuple[float, float]:
    low, high = proportion_confint(k, n, alpha=0.05, method="wilson")
    return float(low), float(high)


def load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def analyze(root: Path, verify: bool = False) -> dict:
    clean_path = root / "results/clean/record_level_results.csv"
    rq2_path = root / "results/clean/rq2_structured_handoffs.csv"
    rq3_path = root / "results/rq3/raw/records-shard-000-of-001.jsonl"
    selected_path = root / "results/rq3/raw/rq3_selected_pairs.json"
    out_dir = root / "results/verification"
    derived_dir = root / "results/rq3/derived"
    out_dir.mkdir(parents=True, exist_ok=True)
    derived_dir.mkdir(parents=True, exist_ok=True)

    clean = pd.read_csv(clean_path)
    selected = set(json.loads(selected_path.read_text(encoding="utf-8"))["pair_ids"])
    clean["gold_n"] = clean["gold"].map(norm)
    clean["pred_n"] = clean["verdict"].map(norm)
    clean["correct_eval"] = clean["gold_n"] == clean["pred_n"]

    clean_summary = (
        clean.groupby("system")
        .agg(
            n=("correct_eval", "size"),
            correct=("correct_eval", "sum"),
            accuracy=("correct_eval", "mean"),
            mean_completion_tokens=("total_completion_tokens", "mean"),
            median_completion_tokens=("total_completion_tokens", "median"),
            mean_latency_seconds=("total_seconds", "mean"),
            median_latency_seconds=("total_seconds", "median"),
        )
        .reset_index()
    )
    clean_summary.to_csv(out_dir / "clean_summary_recomputed.csv", index=False)

    clean15 = clean[clean["pair_id"].isin(selected)].copy()
    base = clean15.set_index(["system", "pair_id", "version"])["correct_eval"]

    rq3_rows = []
    for record in load_jsonl(rq3_path):
        report = record.get("final_report") or {}
        case = record["case"]
        metadata = record.get("metadata", {})
        injection = metadata.get("injection_metadata", {})
        prediction = norm(report.get("verdict"))
        gold = "vulnerable" if str(case.get("version")).lower() == "vulnerable" else "fixed"
        findings = report.get("findings") if isinstance(report.get("findings"), list) else []
        final_spans: list[tuple[int | None, int | None]] = []
        final_cwes: list[str] = []
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            for span in finding.get("spans") or []:
                if isinstance(span, dict):
                    final_spans.append((span.get("start_line"), span.get("end_line")))
            final_cwes.extend(str(item).upper() for item in (finding.get("cwes") or []))
        final_cwes.extend(str(item).upper() for item in (report.get("cwes") or []))
        gold_lines = set(case.get("gold_lines") or [])
        overlap = any(
            isinstance(start, int)
            and isinstance(end, int)
            and bool(gold_lines.intersection(range(start, end + 1)))
            for start, end in final_spans
        )
        corrupt = (injection.get("corrupt_start_line"), injection.get("corrupt_end_line"))

        ref_statuses: list[str] = []
        for stage in record.get("stages", []):
            if stage.get("stage") in {"refuter", "self_critique"}:
                parsed = stage.get("parsed") or {}
                if isinstance(parsed, dict):
                    for decision in parsed.get("decisions") or []:
                        if isinstance(decision, dict):
                            ref_statuses.append(str(decision.get("status")))

        rq3_rows.append(
            {
                "system": record["system"],
                "pair_id": case["pair_id"],
                "version": case["version"],
                "gold": gold,
                "prediction": prediction,
                "correct": prediction == gold,
                "fault": metadata["fault_type"],
                "original_verdict": norm(injection.get("original_verdict")),
                "injected_verdict": norm(injection.get("injected_verdict")),
                "follow_injected": (
                    prediction == norm(injection.get("injected_verdict"))
                    if metadata["fault_type"] == "verdict_inversion"
                    else np.nan
                ),
                "recover_original": (
                    prediction == norm(injection.get("original_verdict"))
                    if metadata["fault_type"] == "verdict_inversion"
                    else np.nan
                ),
                "has_finding": bool(findings),
                "has_span": bool(final_spans),
                "gold_overlap": overlap,
                "exact_corrupt_span": corrupt in final_spans,
                "retain_cwe787": "CWE-787" in set(final_cwes),
                "ref_supported": sum(status == "supported" for status in ref_statuses),
                "ref_refuted": sum(status == "refuted" for status in ref_statuses),
                "ref_corrected": sum(status == "corrected" for status in ref_statuses),
                "ref_uncertain": sum(status == "uncertain" for status in ref_statuses),
                "parse_failed": bool(record.get("parse_failed", False)),
                "stage_failed": any(stage.get("parse_error") for stage in record.get("stages", [])),
                "completion_tokens": record.get("total_completion_tokens"),
                "latency_seconds": record.get("total_latency_seconds"),
            }
        )

    rq3 = pd.DataFrame(rq3_rows)
    rq3.to_csv(derived_dir / "rq3_record_level_recomputed.csv", index=False)
    rq3_summary = (
        rq3.groupby(["system", "fault"])
        .agg(
            n=("correct", "size"),
            accuracy=("correct", "mean"),
            finding_rate=("has_finding", "mean"),
            span_rate=("has_span", "mean"),
            gold_overlap_rate=("gold_overlap", "mean"),
            exact_corrupt_span_rate=("exact_corrupt_span", "mean"),
            cwe787_rate=("retain_cwe787", "mean"),
            final_parse_failures=("parse_failed", "sum"),
            stage_failures=("stage_failed", "sum"),
        )
        .reset_index()
    )
    rq3_summary.to_csv(derived_dir / "rq3_summary_recomputed.csv", index=False)

    vi = rq3[rq3["fault"] == "verdict_inversion"]
    verdict_summary = (
        vi.groupby("system")
        .agg(
            n=("prediction", "size"),
            recovered=("recover_original", "sum"),
            recovery_rate=("recover_original", "mean"),
            followed=("follow_injected", "sum"),
            follow_rate=("follow_injected", "mean"),
            accuracy=("correct", "mean"),
        )
        .reset_index()
    )
    verdict_summary.to_csv(out_dir / "rq3_verdict_inversion.csv", index=False)

    ed = rq3[rq3["fault"] == "evidence_deletion"]
    deletion_summary = (
        ed.groupby("system")
        .agg(
            n=("prediction", "size"),
            finding_rate=("has_finding", "mean"),
            span_rate=("has_span", "mean"),
            gold_overlap_rate=("gold_overlap", "mean"),
            accuracy=("correct", "mean"),
        )
        .reset_index()
    )
    deletion_summary.to_csv(out_dir / "rq3_evidence_deletion.csv", index=False)

    ec = rq3[rq3["fault"] == "evidence_corruption"]
    corruption_summary = (
        ec.groupby("system")
        .agg(
            n=("prediction", "size"),
            finding_rate=("has_finding", "mean"),
            exact_corrupt_span_rate=("exact_corrupt_span", "mean"),
            cwe787_rate=("retain_cwe787", "mean"),
            gold_overlap_rate=("gold_overlap", "mean"),
            accuracy=("correct", "mean"),
        )
        .reset_index()
    )
    corruption_summary.to_csv(out_dir / "rq3_evidence_corruption.csv", index=False)

    rq2 = pd.read_csv(rq2_path)
    rq2_totals = {key: float(value) for key, value in rq2.sum(numeric_only=True).items()}

    prediction_table = clean[clean["system"].isin(["freeform_mas", "structured_mas"])].pivot(
        index=["pair_id", "version"], columns="system", values="pred_n"
    )
    agreement_count = int((prediction_table["freeform_mas"] == prediction_table["structured_mas"]).sum())
    correctness_table = clean[clean["system"].isin(["freeform_mas", "structured_mas"])].pivot(
        index=["pair_id", "version"], columns="system", values="correct_eval"
    )
    free_only = int((correctness_table["freeform_mas"] & ~correctness_table["structured_mas"]).sum())
    structured_only = int((~correctness_table["freeform_mas"] & correctness_table["structured_mas"]).sum())
    discordant = free_only + structured_only
    mcnemar_p = float(binomtest(min(free_only, structured_only), discordant, 0.5).pvalue) if discordant else 1.0

    clean_correctness = clean.pivot(
        index=["pair_id", "version"], columns="system", values="correct_eval"
    ).astype(int)
    cochran = cochrans_q(
        clean_correctness[["self_refine", "freeform_mas", "structured_mas"]].to_numpy()
    )
    clean_pairwise = []
    for first, second in combinations(["self_refine", "freeform_mas", "structured_mas"], 2):
        first_only = int(((clean_correctness[first] == 1) & (clean_correctness[second] == 0)).sum())
        second_only = int(((clean_correctness[first] == 0) & (clean_correctness[second] == 1)).sum())
        n_discordant = first_only + second_only
        p_value = (
            float(binomtest(min(first_only, second_only), n_discordant, 0.5).pvalue)
            if n_discordant
            else 1.0
        )
        clean_pairwise.append(
            {
                "first": first,
                "second": second,
                "first_only_correct": first_only,
                "second_only_correct": second_only,
                "discordant": n_discordant,
                "exact_mcnemar_p": p_value,
            }
        )
    pd.DataFrame(clean_pairwise).to_csv(out_dir / "clean_pairwise_mcnemar.csv", index=False)
    pd.DataFrame(
        [
            {
                "cochran_q": float(cochran.statistic),
                "df": int(cochran.df),
                "p_value": float(cochran.pvalue),
            }
        ]
    ).to_csv(out_dir / "clean_cochran_q.csv", index=False)

    paired_tests = []
    for metric in ["total_completion_tokens", "total_seconds"]:
        pivot = clean.pivot(index=["pair_id", "version"], columns="system", values=metric)
        for first, second in [
            ("structured_mas", "freeform_mas"),
            ("structured_mas", "self_refine"),
            ("freeform_mas", "self_refine"),
        ]:
            statistic, p_value = wilcoxon(pivot[first], pivot[second], zero_method="wilcox")
            paired_tests.append(
                {
                    "metric": metric,
                    "first": first,
                    "second": second,
                    "median_difference": float(np.median(pivot[first] - pivot[second])),
                    "mean_difference": float(np.mean(pivot[first] - pivot[second])),
                    "statistic": float(statistic),
                    "p_value": float(p_value),
                }
            )
    pd.DataFrame(paired_tests).to_csv(out_dir / "efficiency_wilcoxon.csv", index=False)

    key_intervals = []
    for label, frame, column in [
        ("verdict_recovery", vi, "recover_original"),
        ("verdict_follow", vi, "follow_injected"),
        ("deletion_finding", ed, "has_finding"),
        ("deletion_gold_overlap", ed, "gold_overlap"),
        ("corruption_cwe787", ec, "retain_cwe787"),
        ("corruption_exact_span", ec, "exact_corrupt_span"),
    ]:
        for system, group in frame.groupby("system"):
            k = int(group[column].sum())
            n = len(group)
            low, high = wilson(k, n)
            key_intervals.append(
                {
                    "metric": label,
                    "system": system,
                    "count": k,
                    "n": n,
                    "rate": k / n,
                    "wilson_low": low,
                    "wilson_high": high,
                }
            )
    pd.DataFrame(key_intervals).to_csv(out_dir / "key_wilson_intervals.csv", index=False)

    metric_specs = [
        ("verdict_recovery", vi, "recover_original"),
        ("verdict_follow", vi, "follow_injected"),
        ("deletion_finding", ed, "has_finding"),
        ("deletion_gold_overlap", ed, "gold_overlap"),
        ("corruption_cwe787", ec, "retain_cwe787"),
        ("corruption_exact_span", ec, "exact_corrupt_span"),
    ]
    fault_pairwise_rows = []
    for metric_name, frame, column in metric_specs:
        pivot = frame.pivot(
            index=["pair_id", "version"], columns="system", values=column
        ).astype(bool)
        family_rows = []
        for first, second in combinations(["self_refine", "freeform_mas", "structured_mas"], 2):
            first_only = int((pivot[first] & ~pivot[second]).sum())
            second_only = int((~pivot[first] & pivot[second]).sum())
            n_discordant = first_only + second_only
            raw_p = (
                float(binomtest(min(first_only, second_only), n_discordant, 0.5).pvalue)
                if n_discordant
                else 1.0
            )
            family_rows.append(
                {
                    "metric": metric_name,
                    "first": first,
                    "second": second,
                    "first_only": first_only,
                    "second_only": second_only,
                    "discordant": n_discordant,
                    "raw_p": raw_p,
                }
            )
        order = sorted(range(len(family_rows)), key=lambda idx: family_rows[idx]["raw_p"])
        running = 0.0
        adjusted = [1.0] * len(family_rows)
        for rank, idx in enumerate(order):
            candidate = min(1.0, family_rows[idx]["raw_p"] * (len(family_rows) - rank))
            running = max(running, candidate)
            adjusted[idx] = running
        for row, adjusted_p in zip(family_rows, adjusted):
            row["holm_adjusted_p"] = adjusted_p
            fault_pairwise_rows.append(row)
    pd.DataFrame(fault_pairwise_rows).to_csv(out_dir / "rq3_pairwise_mcnemar_holm.csv", index=False)

    accuracy_drops = []
    for (system, fault), group in rq3.groupby(["system", "fault"]):
        keys = [(system, pair, version) for pair, version in zip(group["pair_id"], group["version"])]
        base_values = np.array([bool(base.loc[key]) for key in keys])
        fault_values = group["correct"].to_numpy(bool)
        base_only = int(np.sum(base_values & ~fault_values))
        fault_only = int(np.sum(~base_values & fault_values))
        n_discordant = base_only + fault_only
        p_value = (
            float(binomtest(min(base_only, fault_only), n_discordant, 0.5).pvalue)
            if n_discordant
            else 1.0
        )
        accuracy_drops.append(
            {
                "system": system,
                "fault": fault,
                "clean_accuracy_selected": float(base_values.mean()),
                "fault_accuracy": float(fault_values.mean()),
                "accuracy_drop": float(base_values.mean() - fault_values.mean()),
                "clean_only_correct": base_only,
                "fault_only_correct": fault_only,
                "exact_mcnemar_p": p_value,
            }
        )
    pd.DataFrame(accuracy_drops).to_csv(out_dir / "rq3_accuracy_drops.csv", index=False)

    verification = {
        "clean_records": int(len(clean)),
        "rq3_records": int(len(rq3)),
        "rq3_final_parse_failures": int(rq3["parse_failed"].sum()),
        "rq3_stage_failures": int(rq3["stage_failed"].sum()),
        "clean_cochran_q": {
            "statistic": float(cochran.statistic),
            "df": int(cochran.df),
            "p_value": float(cochran.pvalue),
        },
        "free_structured_prediction_agreement": {
            "count": agreement_count,
            "n": int(len(prediction_table)),
            "rate": agreement_count / len(prediction_table),
            "free_only_correct": free_only,
            "structured_only_correct": structured_only,
            "exact_mcnemar_p": mcnemar_p,
        },
        "rq2_totals": rq2_totals,
    }
    (out_dir / "verification_summary.json").write_text(json.dumps(verification, indent=2), encoding="utf-8")

    if verify:
        assert len(clean) == 174
        assert clean.groupby("system").size().to_dict() == {
            "freeform_mas": 58,
            "self_refine": 58,
            "structured_mas": 58,
        }
        assert len(rq3) == 270
        assert rq3.groupby("system").size().to_dict() == {
            "freeform_mas": 90,
            "self_refine": 90,
            "structured_mas": 90,
        }
        assert int(rq3["parse_failed"].sum()) == 1
        assert int(rq3["stage_failed"].sum()) == 3
        assert math.isclose(float(cochran.statistic), 0.6153846153846154, abs_tol=1e-12)
        assert math.isclose(float(cochran.pvalue), 0.7351414805916845, abs_tol=1e-12)
        rq3_pairwise = pd.DataFrame(fault_pairwise_rows)
        key_p = rq3_pairwise[
            (rq3_pairwise["metric"] == "verdict_recovery")
            & (rq3_pairwise["first"] == "freeform_mas")
            & (rq3_pairwise["second"] == "structured_mas")
        ]["holm_adjusted_p"].iloc[0]
        assert key_p < 0.001
        key_p = rq3_pairwise[
            (rq3_pairwise["metric"] == "corruption_cwe787")
            & (rq3_pairwise["first"] == "freeform_mas")
            & (rq3_pairwise["second"] == "structured_mas")
        ]["holm_adjusted_p"].iloc[0]
        assert key_p < 0.001
        expected_accuracy = {
            "freeform_mas": 30 / 58,
            "self_refine": 28 / 58,
            "structured_mas": 30 / 58,
        }
        actual_accuracy = dict(zip(clean_summary["system"], clean_summary["accuracy"]))
        for system, expected in expected_accuracy.items():
            assert math.isclose(actual_accuracy[system], expected, rel_tol=0, abs_tol=1e-12)
        assert agreement_count == 54
        assert free_only == 2 and structured_only == 2 and math.isclose(mcnemar_p, 1.0)

        expected_rq3 = {
            ("structured_mas", "verdict_inversion", "recovery_rate"): 29 / 30,
            ("structured_mas", "verdict_inversion", "follow_rate"): 0.0,
            ("structured_mas", "evidence_deletion", "finding_rate"): 1.0,
            ("structured_mas", "evidence_corruption", "cwe787_rate"): 28 / 30,
            ("structured_mas", "evidence_corruption", "exact_corrupt_span_rate"): 10 / 30,
        }
        lookup = {}
        for _, row in verdict_summary.iterrows():
            lookup[(row["system"], "verdict_inversion", "recovery_rate")] = row["recovery_rate"]
            lookup[(row["system"], "verdict_inversion", "follow_rate")] = row["follow_rate"]
        for _, row in deletion_summary.iterrows():
            lookup[(row["system"], "evidence_deletion", "finding_rate")] = row["finding_rate"]
        for _, row in corruption_summary.iterrows():
            lookup[(row["system"], "evidence_corruption", "cwe787_rate")] = row["cwe787_rate"]
            lookup[(row["system"], "evidence_corruption", "exact_corrupt_span_rate")] = row[
                "exact_corrupt_span_rate"
            ]
        for key, expected in expected_rq3.items():
            assert math.isclose(float(lookup[key]), expected, rel_tol=0, abs_tol=1e-12), (key, lookup[key])
        print("All artifact verification checks passed.")

    return verification


def main() -> None:
    parser = argparse.ArgumentParser(description="Recompute and verify the paper's clean and RQ3 results.")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args()
    verification = analyze(args.root.resolve(), verify=args.verify)
    print(json.dumps(verification, indent=2))


if __name__ == "__main__":
    main()
