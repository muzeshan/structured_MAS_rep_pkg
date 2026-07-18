from __future__ import annotations

import hashlib
import json
import random
from pathlib import Path
from typing import Any

import pandas as pd
from scipy.stats import fisher_exact
from sklearn.metrics import cohen_kappa_score
from statsmodels.stats.multitest import multipletests

from vulhandoff.analysis import load_experiment_records, verdict_label
from vulhandoff.data import load_pairs
from vulhandoff.utils import ensure_dir, numbered_code


RATING_FIELDS = [
    "analyst_claim_supported",
    "analyst_evidence_complete",
    "evidence_retained_to_refuter",
    "evidence_distorted",
    "downstream_repaired_error",
    "final_evidence_supported",
    "final_verdict_supported_by_code",
]

PACKET_COLUMNS = [
    "blind_item_id",
    "system_blind",
    "language",
    "numbered_code",
    "analyst_handoff",
    "refuter_handoff",
    "final_report",
    *RATING_FIELDS,
    "notes",
]


def export_annotation_packets(
    results_path: str,
    pairs_path: str,
    output_dir: str,
    seed: int = 20260712,
    systems: list[str] | None = None,
    versions: list[str] | None = None,
) -> tuple[Path, Path, Path]:
    records = load_experiment_records(results_path)
    selected_pairs = {pair.pair_id for pair in load_pairs(pairs_path)}
    records = [record for record in records if record.case.pair_id in selected_pairs]
    if systems:
        records = [record for record in records if record.system in systems]
    if versions:
        records = [record for record in records if record.case.version in versions]
    if not records:
        raise ValueError("No experiment records matched the annotation pair selection")
    first_repetition = min(record.repetition for record in records)
    records = [record for record in records if record.repetition == first_repetition]

    rng = random.Random(seed)
    system_names = sorted({record.system for record in records})
    shuffled_labels = [f"System-{chr(65 + index)}" for index in range(len(system_names))]
    rng.shuffle(shuffled_labels)
    blind_system = dict(zip(system_names, shuffled_labels))

    packets: list[dict[str, Any]] = []
    keys: list[dict[str, Any]] = []
    for record in records:
        blind_id = hashlib.sha256(f"{record.run_id}|{seed}".encode()).hexdigest()[:18]
        final_payload = record.final_report.model_dump(mode="json") if record.final_report else {}
        packets.append(
            {
                "blind_item_id": blind_id,
                "system_blind": blind_system[record.system],
                "language": record.case.language,
                "numbered_code": numbered_code(record.case.code),
                "analyst_handoff": record.stages[0].raw_text if record.stages else "",
                "refuter_handoff": record.stages[1].raw_text if len(record.stages) > 1 else "",
                "final_report": json.dumps(final_payload, ensure_ascii=False),
                **{field: "" for field in RATING_FIELDS},
                "notes": "",
            }
        )
        keys.append(
            {
                "blind_item_id": blind_id,
                "run_id": record.run_id,
                "system": record.system,
                "model": record.model,
                "case_id": record.case.case_id,
                "pair_id": record.case.pair_id,
                "version": record.case.version,
                "gold_label": record.case.label,
                "gold_cwes": json.dumps(record.case.cwe_ids),
                "patch_proxy_lines": json.dumps(record.case.gold_lines),
            }
        )

    output = ensure_dir(output_dir)
    packet_a = output / "annotation_packet_A.csv"
    packet_b = output / "annotation_packet_B.csv"
    key_path = output / "annotation_key_PRIVATE.csv"
    order_a = list(packets)
    order_b = list(packets)
    rng.shuffle(order_a)
    rng.shuffle(order_b)
    pd.DataFrame(order_a, columns=PACKET_COLUMNS).to_csv(packet_a, index=False)
    pd.DataFrame(order_b, columns=PACKET_COLUMNS).to_csv(packet_b, index=False)
    pd.DataFrame(keys).to_csv(key_path, index=False)
    return packet_a, packet_b, key_path


def annotation_agreement(
    annotator_a: str,
    annotator_b: str,
    key_path: str | None = None,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    first = pd.read_csv(annotator_a, dtype=str).fillna("")
    second = pd.read_csv(annotator_b, dtype=str).fillna("")
    merged = first.merge(second, on="blind_item_id", suffixes=("_a", "_b"))
    rows: list[dict[str, Any]] = []
    for field in RATING_FIELDS:
        left = merged[f"{field}_a"].str.lower().str.strip()
        right = merged[f"{field}_b"].str.lower().str.strip()
        valid = (left != "") & (right != "")
        if valid.sum() == 0:
            raw = float("nan")
            kappa = float("nan")
        else:
            raw = float((left[valid] == right[valid]).mean())
            try:
                kappa = float(cohen_kappa_score(left[valid], right[valid]))
            except Exception:
                kappa = float("nan")
        rows.append(
            {
                "field": field,
                "n_double_annotated": int(valid.sum()),
                "raw_agreement": raw,
                "cohen_kappa": kappa,
            }
        )
    if key_path:
        merged = merged.merge(pd.read_csv(key_path, dtype=str), on="blind_item_id", how="left")
    return merged, pd.DataFrame(rows)


def export_adjudication_sheet(merged: pd.DataFrame, output_path: str) -> Path:
    disagreement = pd.Series(False, index=merged.index)
    for field in RATING_FIELDS:
        left = merged[f"{field}_a"].fillna("").str.lower().str.strip()
        right = merged[f"{field}_b"].fillna("").str.lower().str.strip()
        disagreement |= (left != "") & (right != "") & (left != right)
    subset = merged[disagreement].copy()
    for field in RATING_FIELDS:
        subset[f"{field}_adjudicated"] = ""
    subset["adjudication_notes"] = ""
    path = Path(output_path)
    ensure_dir(path.parent)
    subset.to_csv(path, index=False)
    return path


def summarize_adjudicated_annotations(
    merged_path: str,
    key_path: str,
    output_dir: str,
    adjudicated_path: str | None = None,
    results_path: str | None = None,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    merged = pd.read_csv(merged_path, dtype=str).fillna("")
    if "system" not in merged.columns:
        merged = merged.merge(pd.read_csv(key_path, dtype=str), on="blind_item_id", how="left")
    adjudicated = None
    if adjudicated_path and Path(adjudicated_path).exists():
        adjudicated = pd.read_csv(adjudicated_path, dtype=str).fillna("").set_index("blind_item_id")

    resolved_rows: list[dict[str, Any]] = []
    for _, row in merged.iterrows():
        result: dict[str, Any] = {
            "blind_item_id": row["blind_item_id"],
            "system": row.get("system", "unknown"),
            "model": row.get("model", "unknown"),
            "case_id": row.get("case_id", ""),
            "pair_id": row.get("pair_id", ""),
            "version": row.get("version", ""),
        }
        for field in RATING_FIELDS:
            left = str(row.get(f"{field}_a", "")).strip().lower()
            right = str(row.get(f"{field}_b", "")).strip().lower()
            value = left if left and left == right else ""
            if not value and adjudicated is not None and row["blind_item_id"] in adjudicated.index:
                value = str(adjudicated.loc[row["blind_item_id"]].get(f"{field}_adjudicated", "")).strip().lower()
            result[field] = value
        resolved_rows.append(result)
    resolved = pd.DataFrame(resolved_rows)
    if results_path:
        result_records = load_experiment_records(results_path)
        outcome_rows = []
        pair_correct_map: dict[tuple[str, str, int], bool] = {}
        by_pair: dict[tuple[str, str, int], dict[str, int | None]] = {}
        for record in result_records:
            predicted = verdict_label(record.final_report)
            key = (record.system, record.case.pair_id, record.repetition)
            by_pair.setdefault(key, {})[record.case.version] = predicted
        for key, versions in by_pair.items():
            pair_correct_map[key] = versions.get("vulnerable") == 1 and versions.get("fixed") == 0
        for record in result_records:
            predicted = verdict_label(record.final_report)
            outcome_rows.append(
                {
                    "run_id": record.run_id,
                    "final_correct": predicted == record.case.label,
                    "abstained": predicted is None,
                    "pair_correct": pair_correct_map.get(
                        (record.system, record.case.pair_id, record.repetition), False
                    ),
                }
            )
        outcomes = pd.DataFrame(outcome_rows)
        key_frame = pd.read_csv(key_path, dtype=str)
        resolved = resolved.merge(key_frame[["blind_item_id", "run_id"]], on="blind_item_id", how="left")
        resolved = resolved.merge(outcomes, on="run_id", how="left")

    summary_rows: list[dict[str, Any]] = []
    for (model, system), group in resolved.groupby(["model", "system"], dropna=False):
        for field in RATING_FIELDS:
            valid = group[field][group[field] != ""]
            summary_rows.append(
                {
                    "model": model,
                    "system": system,
                    "field": field,
                    "n_resolved": len(valid),
                    "yes_rate": float((valid == "yes").mean()) if len(valid) else float("nan"),
                    "partial_rate": float((valid == "partial").mean()) if len(valid) else float("nan"),
                    "uncertain_rate": float((valid == "uncertain").mean()) if len(valid) else float("nan"),
                    "category_counts": json.dumps(valid.value_counts().to_dict()),
                }
            )
    summary = pd.DataFrame(summary_rows)
    output = ensure_dir(output_dir)
    resolved.to_csv(output / "resolved_annotations.csv", index=False)
    summary.to_csv(output / "manual_annotation_summary.csv", index=False)

    association_rows: list[dict[str, Any]] = []
    if results_path and "final_correct" in resolved.columns:
        failure_definitions = {
            "analyst_claim_unsupported_or_partial": resolved["analyst_claim_supported"].isin(["no", "partial"]),
            "analyst_evidence_incomplete": resolved["analyst_evidence_complete"].isin(["no", "partial"]),
            "evidence_not_fully_retained": resolved["evidence_retained_to_refuter"].isin(["no", "partial"]),
            "evidence_distorted": resolved["evidence_distorted"].eq("yes"),
            "final_evidence_unsupported_or_partial": resolved["final_evidence_supported"].isin(["no", "partial"]),
        }
        local_rows: list[dict[str, Any]] = []
        incorrect = ~resolved["final_correct"].fillna(False).astype(bool)
        for name, failure in failure_definitions.items():
            valid = pd.Series(True, index=resolved.index)
            # Exclude unresolved/uncertain ratings from the binary association.
            if name == "analyst_evidence_incomplete":
                valid = resolved["analyst_evidence_complete"].isin(["yes", "no", "partial"])
            elif name == "evidence_not_fully_retained":
                valid = resolved["evidence_retained_to_refuter"].isin(["yes", "no", "partial"])
            elif name == "evidence_distorted":
                valid = resolved["evidence_distorted"].isin(["yes", "no"])
            elif name == "final_evidence_unsupported_or_partial":
                valid = resolved["final_evidence_supported"].isin(["yes", "no", "partial"])
            elif name == "analyst_claim_unsupported_or_partial":
                valid = resolved["analyst_claim_supported"].isin(["yes", "no", "partial"])
            f = failure[valid]
            y = incorrect[valid]
            table = [
                [int((f & y).sum()), int((f & ~y).sum())],
                [int((~f & y).sum()), int((~f & ~y).sum())],
            ]
            odds_ratio, p_value = fisher_exact(table)
            local_rows.append(
                {
                    "failure_indicator": name,
                    "n": int(valid.sum()),
                    "failure_and_incorrect": table[0][0],
                    "failure_and_correct": table[0][1],
                    "no_failure_and_incorrect": table[1][0],
                    "no_failure_and_correct": table[1][1],
                    "odds_ratio_incorrect": float(odds_ratio),
                    "p_value": float(p_value),
                }
            )
        if local_rows:
            adjusted = multipletests([row["p_value"] for row in local_rows], method="holm")[1]
            for row, p_holm in zip(local_rows, adjusted):
                row["p_holm"] = float(p_holm)
                association_rows.append(row)
    associations = pd.DataFrame(association_rows)
    associations.to_csv(output / "manual_annotation_associations.csv", index=False)

    try:
        (output / "manual_annotation_summary.tex").write_text(
            summary.to_latex(index=False, float_format=lambda value: f"{value:.3f}"),
            encoding="utf-8",
        )
        if not associations.empty:
            (output / "manual_annotation_associations.tex").write_text(
                associations.to_latex(index=False, float_format=lambda value: f"{value:.3f}"),
                encoding="utf-8",
            )
    except Exception:
        pass
    return resolved, summary
