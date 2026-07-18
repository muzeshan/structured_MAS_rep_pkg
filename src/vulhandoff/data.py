from __future__ import annotations

import difflib
import json
import random
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

from vulhandoff.config import DatasetConfig
from vulhandoff.models import CaseSample, PairSample, normalize_cwe_list
from vulhandoff.utils import (
    ensure_dir,
    first_present,
    normalize_identifier,
    normalize_list,
    parse_maybe_serialized,
    read_jsonl,
    read_loose_records,
    stable_hash,
    write_jsonl,
)


def normalize_code(value: Any) -> str:
    if value is None:
        return ""
    return str(value).replace("\r\n", "\n").replace("\r", "\n").strip("\n")


def label_value(row: dict[str, Any]) -> int:
    value = first_present(row, ["is_vulnerable", "label", "target", "vulnerable"], 0)
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "yes", "vulnerable", "1"}:
            return 1
        if lowered in {"false", "no", "not_vulnerable", "non-vulnerable", "0"}:
            return 0
    return int(bool(value))


def local_diff_lines(vulnerable_code: str, fixed_code: str) -> tuple[list[int], list[int]]:
    """Map a textual patch to one-based local line positions in both versions.

    Insert-only fixes have no deleted vulnerable line; in that case the nearest vulnerable-side
    anchor is included. Patch overlap is therefore a localization proxy, not root-cause ground truth.
    """
    before = normalize_code(vulnerable_code).split("\n")
    after = normalize_code(fixed_code).split("\n")
    matcher = difflib.SequenceMatcher(a=before, b=after, autojunk=False)
    before_changed: set[int] = set()
    after_changed: set[int] = set()
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            continue
        if i1 < i2:
            before_changed.update(range(i1 + 1, i2 + 1))
        else:
            anchor = min(max(i1, 1), max(len(before), 1))
            before_changed.add(anchor)
        if j1 < j2:
            after_changed.update(range(j1 + 1, j2 + 1))
        else:
            anchor = min(max(j1, 1), max(len(after), 1))
            after_changed.add(anchor)
    return sorted(before_changed), sorted(after_changed)


def map_changed_statements(code: str, value: Any) -> list[int]:
    parsed = parse_maybe_serialized(value)
    if parsed is None:
        return []
    if isinstance(parsed, str):
        candidates = [parsed]
    elif isinstance(parsed, dict):
        candidates = [str(item) for item in parsed.values()]
    elif isinstance(parsed, (list, tuple, set)):
        candidates = []
        for item in parsed:
            if isinstance(item, dict):
                candidates.append(str(first_present(item, ["code", "statement", "text", "line"], "")))
            elif isinstance(item, (list, tuple)) and len(item) >= 2:
                candidates.append(str(item[-1]))
            elif isinstance(item, str):
                candidates.append(item)
    else:
        candidates = []
    code_lines = normalize_code(code).split("\n")
    normalized = [re.sub(r"\s+", " ", line.strip()) for line in code_lines]
    result: set[int] = set()
    for candidate in candidates:
        needle = re.sub(r"\s+", " ", candidate.strip())
        if not needle or needle.isdigit():
            continue
        for index, line in enumerate(normalized, start=1):
            if needle == line or (len(needle) >= 5 and (needle in line or line in needle)):
                result.add(index)
    return sorted(result)


def _guess_language(path: Any, code: str) -> str:
    suffix = str(path or "").lower()
    if suffix.endswith(".py"):
        return "python"
    if suffix.endswith((".cc", ".cpp", ".cxx", ".hpp", ".hh", ".hxx")):
        return "cpp"
    if suffix.endswith(".java"):
        return "java"
    if suffix.endswith((".js", ".jsx", ".ts", ".tsx")):
        return "javascript"
    if suffix.endswith(".c"):
        return "c"
    if "std::" in code or "template<" in code:
        return "cpp"
    if re.search(r"^\s*def\s+\w+\(", code, re.M):
        return "python"
    return "c"


def _make_pair(
    dataset: str,
    vulnerable_row: dict[str, Any],
    fixed_row: dict[str, Any],
    vulnerable_code: str,
    fixed_code: str,
    source_key: str,
) -> PairSample | None:
    vulnerable_code = normalize_code(vulnerable_code)
    fixed_code = normalize_code(fixed_code)
    if not vulnerable_code or not fixed_code or vulnerable_code == fixed_code:
        return None
    diff_v, diff_f = local_diff_lines(vulnerable_code, fixed_code)
    statement_v = map_changed_statements(
        vulnerable_code,
        first_present(vulnerable_row, ["changed_statements", "changed_lines", "vulnerable_statements"]),
    )
    statement_f = map_changed_statements(
        fixed_code,
        first_present(fixed_row, ["changed_statements", "changed_lines", "fixed_statements"]),
    )
    project = str(
        first_present(vulnerable_row, ["project", "project_name", "repo", "repo_name", "repository", "package"], "unknown")
    )
    file_path = first_present(vulnerable_row, ["filepath", "file_path", "path", "filename", "file"])
    function_name = first_present(vulnerable_row, ["func_name", "function_name", "name"])
    cves = normalize_list(first_present(vulnerable_row, ["cve_list", "cves", "cve", "CVE"]))
    cwes = normalize_cwe_list(first_present(vulnerable_row, ["cwe_list", "cwes", "cwe", "CWE"]))
    pair_hash = stable_hash(vulnerable_code, fixed_code, length=12)
    return PairSample(
        pair_id=f"{dataset}::{source_key}::{pair_hash}",
        dataset=dataset,
        language=_guess_language(file_path, vulnerable_code),
        project=project,
        cve_ids=cves,
        cwe_ids=cwes,
        file_path=str(file_path) if file_path else None,
        function_name=str(function_name) if function_name else None,
        vulnerable_code=vulnerable_code,
        fixed_code=fixed_code,
        gold_vulnerable_lines=sorted(set(diff_v) | set(statement_v)),
        gold_fixed_lines=sorted(set(diff_f) | set(statement_f)),
        metadata={
            "source_key": source_key,
            "project_url": first_present(vulnerable_row, ["project_url", "repo_url"]),
            "commit_id": first_present(vulnerable_row, ["commit_id", "commit", "commit_hash"]),
            "commit_message": first_present(vulnerable_row, ["commit_message", "message"]),
            "original_changed_lines": first_present(vulnerable_row, ["changed_lines"]),
            "original_changed_statements": first_present(vulnerable_row, ["changed_statements"]),
        },
    )


def load_secvuleval(config: DatasetConfig) -> list[PairSample]:
    from datasets import load_dataset

    dataset = load_dataset(
        config.hf_dataset_id,
        split=config.hf_split,
        revision=config.hf_revision,
    )
    return rows_to_secvuleval_pairs([dict(item) for item in dataset])


def rows_to_secvuleval_pairs(rows: list[dict[str, Any]]) -> list[PairSample]:
    """Convert the public SecVulEval row schema into vulnerable/fixed pairs.

    The public mirror uses fields such as ``func_body``, ``is_vulnerable`` and
    ``fixed_func_idx``. The fixed reference has appeared as either a dataset row
    position or the row's ``idx`` value, so both representations are supported and
    checked against the expected non-vulnerable label.
    """
    by_identifier: dict[str, dict[str, Any]] = {}
    for row_index, row in enumerate(rows):
        for value in [row_index, first_present(row, ["func_id", "idx", "id", "sample_id"])]:
            key = normalize_identifier(value)
            if key is not None:
                by_identifier[key] = row

    pairs: list[PairSample] = []
    for row_index, row in enumerate(rows):
        if label_value(row) != 1:
            continue
        fixed_reference = first_present(
            row,
            ["fixed_func_idx", "fixed_func_id", "fixed_id", "patched_id", "pair_id"],
        )
        fixed_row: dict[str, Any] | None = None
        reference_key = normalize_identifier(fixed_reference)
        # Prefer a direct identifier match because the public description states that
        # the reference points to the row's `idx`; retain positional lookup for mirrors
        # that materialize it as a zero-based row number.
        if reference_key is not None:
            fixed_row = by_identifier.get(reference_key)
        if fixed_row is None and fixed_reference is not None:
            try:
                numeric = int(float(str(fixed_reference)))
                if 0 <= numeric < len(rows):
                    fixed_row = rows[numeric]
            except Exception:
                pass
        if fixed_row is not None and label_value(fixed_row) == 1:
            fixed_row = None
        if fixed_row is None:
            fixed_row = _find_matching_fixed(row, rows)
        if fixed_row is None:
            continue
        vulnerable_code = first_present(row, ["func_body", "function", "func", "code", "source_code"])
        fixed_code = first_present(fixed_row, ["func_body", "function", "func", "code", "source_code"])
        source_key = normalize_identifier(first_present(row, ["func_id", "idx", "id"], row_index)) or str(row_index)
        pair = _make_pair("secvuleval", row, fixed_row, vulnerable_code, fixed_code, source_key)
        if pair is not None:
            pair.metadata["fixed_reference"] = fixed_reference
            pairs.append(pair)
    return pairs


def _find_matching_fixed(vulnerable: dict[str, Any], rows: list[dict[str, Any]]) -> dict[str, Any] | None:
    project = first_present(vulnerable, ["project", "project_name", "repo", "repo_name"])
    function_name = first_present(vulnerable, ["func_name", "function_name", "name"])
    cves = set(normalize_list(first_present(vulnerable, ["cve_list", "cves", "cve"])))
    for candidate in rows:
        if label_value(candidate) != 0:
            continue
        if project is not None and first_present(candidate, ["project", "project_name", "repo", "repo_name"]) != project:
            continue
        if function_name is not None and first_present(candidate, ["func_name", "function_name", "name"]) != function_name:
            continue
        candidate_cves = set(normalize_list(first_present(candidate, ["cve_list", "cves", "cve"])))
        if cves and candidate_cves and not cves.intersection(candidate_cves):
            continue
        return candidate
    return None


def load_primevul(config: DatasetConfig) -> list[PairSample]:
    if not config.input_path:
        raise ValueError("dataset.input_path is required for PrimeVul")
    rows = read_loose_records(config.input_path)
    pairs: list[PairSample] = []
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        key = first_present(row, ["pair_id", "paired_id", "pair_idx", "group_id"])
        if key is not None:
            groups[str(key)].append(row)
    used_ids: set[int] = set()
    for key, items in groups.items():
        vulnerable = next((item for item in items if label_value(item) == 1), None)
        fixed = next((item for item in items if label_value(item) == 0), None)
        if vulnerable is None or fixed is None:
            continue
        pair = _make_pair(
            "primevul",
            vulnerable,
            fixed,
            first_present(vulnerable, ["func", "function", "code", "source_code"]),
            first_present(fixed, ["func", "function", "code", "source_code"]),
            key,
        )
        if pair is not None:
            pairs.append(pair)
            used_ids.update(id(item) for item in items)
    remaining = [row for row in rows if id(row) not in used_ids]
    for start in range(0, len(remaining) - 1, 2):
        first, second = remaining[start], remaining[start + 1]
        if label_value(first) == label_value(second):
            continue
        vulnerable = first if label_value(first) == 1 else second
        fixed = second if label_value(first) == 1 else first
        pair = _make_pair(
            "primevul",
            vulnerable,
            fixed,
            first_present(vulnerable, ["func", "function", "code", "source_code"]),
            first_present(fixed, ["func", "function", "code", "source_code"]),
            f"adjacent-{start // 2}",
        )
        if pair is not None:
            pairs.append(pair)
    return pairs


def load_pyvul(config: DatasetConfig) -> list[PairSample]:
    if not config.input_path:
        raise ValueError("dataset.input_path is required for PyVul")
    rows = read_loose_records(config.input_path)
    before_aliases = [
        "vulnerable_code", "vul_code", "vul_func", "before", "old_code", "pre_code",
        "function_before", "func_before", "original_function",
    ]
    after_aliases = [
        "fixed_code", "patch_code", "fixed_func", "after", "new_code", "post_code",
        "function_after", "func_after", "patched_function",
    ]
    pairs: list[PairSample] = []
    consumed: set[int] = set()
    for row_index, row in enumerate(rows):
        before = first_present(row, before_aliases)
        after = first_present(row, after_aliases)
        if before is None or after is None:
            continue
        key = str(first_present(row, ["pair_id", "commit_id", "commit", "cve", "advisory_id"], row_index))
        pair = _make_pair("pyvul", row, row, before, after, key)
        if pair is not None:
            pairs.append(pair)
            consumed.add(id(row))
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        if id(row) in consumed:
            continue
        key = first_present(row, ["pair_id", "commit_id", "commit", "cve", "advisory_id", "function_id"])
        if key is not None:
            groups[str(key)].append(row)
    for key, items in groups.items():
        vulnerable = next((item for item in items if label_value(item) == 1), None)
        fixed = next((item for item in items if label_value(item) == 0), None)
        if vulnerable is None or fixed is None:
            continue
        pair = _make_pair(
            "pyvul",
            vulnerable,
            fixed,
            first_present(vulnerable, ["function", "func", "func_body", "code", "source_code"]),
            first_present(fixed, ["function", "func", "func_body", "code", "source_code"]),
            key,
        )
        if pair is not None:
            pairs.append(pair)
    if not pairs:
        columns = sorted({key for row in rows[:50] for key in row})
        raise ValueError(
            "Could not map the PyVul export to vulnerable/fixed pairs. "
            f"Observed fields: {columns}. Inspect the file and add aliases in vulhandoff/data.py."
        )
    return pairs


def pair_to_cases(pair: PairSample) -> list[CaseSample]:
    shared = {
        "pair_id": pair.pair_id,
        "dataset": pair.dataset,
        "language": pair.language,
        "project": pair.project,
        "cve_ids": pair.cve_ids,
        "cwe_ids": pair.cwe_ids,
        "file_path": pair.file_path,
        "function_name": pair.function_name,
        "metadata": pair.metadata,
    }
    return [
        CaseSample(
            case_id=f"{pair.pair_id}::vulnerable",
            version="vulnerable",
            label=1,
            code=pair.vulnerable_code,
            gold_lines=pair.gold_vulnerable_lines,
            **shared,
        ),
        CaseSample(
            case_id=f"{pair.pair_id}::fixed",
            version="fixed",
            label=0,
            code=pair.fixed_code,
            gold_lines=pair.gold_fixed_lines,
            **shared,
        ),
    ]


def _valid_pair(pair: PairSample, config: DatasetConfig) -> bool:
    vulnerable_lines = pair.vulnerable_code.splitlines()
    fixed_lines = pair.fixed_code.splitlines()
    if not config.min_code_lines <= len(vulnerable_lines) <= config.max_code_lines:
        return False
    if not config.min_code_lines <= len(fixed_lines) <= config.max_code_lines:
        return False
    if len(pair.vulnerable_code) > config.max_code_chars or len(pair.fixed_code) > config.max_code_chars:
        return False
    if pair.vulnerable_code.strip() == pair.fixed_code.strip():
        return False
    return True


def deduplicate_pairs(pairs: Iterable[PairSample]) -> list[PairSample]:
    result: list[PairSample] = []
    seen: set[str] = set()
    for pair in pairs:
        key = stable_hash(pair.vulnerable_code, pair.fixed_code, length=64)
        if key in seen:
            continue
        seen.add(key)
        result.append(pair)
    return result


def balanced_sample(
    pairs: list[PairSample],
    max_pairs: int | None,
    max_per_project: int,
    seed: int,
) -> list[PairSample]:
    rng = random.Random(seed)
    by_project: dict[str, list[PairSample]] = defaultdict(list)
    for pair in pairs:
        by_project[pair.project or pair.pair_id].append(pair)
    candidates: list[PairSample] = []
    for items in by_project.values():
        rng.shuffle(items)
        candidates.extend(items[:max_per_project])
    by_cwe: dict[str, list[PairSample]] = defaultdict(list)
    for pair in candidates:
        by_cwe[pair.cwe_ids[0] if pair.cwe_ids else "CWE-UNKNOWN"].append(pair)
    for items in by_cwe.values():
        rng.shuffle(items)
    keys = list(by_cwe)
    rng.shuffle(keys)
    selected: list[PairSample] = []
    while keys and (max_pairs is None or len(selected) < max_pairs):
        remaining_keys: list[str] = []
        for key in keys:
            if by_cwe[key]:
                selected.append(by_cwe[key].pop())
                if max_pairs is not None and len(selected) >= max_pairs:
                    break
            if by_cwe[key]:
                remaining_keys.append(key)
        keys = remaining_keys
    return selected


def project_disjoint_split(
    pairs: list[PairSample], development_target: int, seed: int
) -> tuple[list[PairSample], list[PairSample]]:
    if development_target <= 0:
        return [], list(pairs)
    groups: dict[str, list[PairSample]] = defaultdict(list)
    for pair in pairs:
        groups[pair.project or pair.pair_id].append(pair)
    projects = list(groups)
    random.Random(seed).shuffle(projects)
    # Subset-sum over whole project groups; max project size is bounded upstream.
    reachable: dict[int, list[str]] = {0: []}
    limit = min(len(pairs), development_target + max(len(groups[p]) for p in projects))
    for project in projects:
        size = len(groups[project])
        updates: dict[int, list[str]] = {}
        for total, chosen in list(reachable.items()):
            candidate = total + size
            if candidate <= limit and candidate not in reachable and candidate not in updates:
                updates[candidate] = chosen + [project]
        reachable.update(updates)
    best_total = min(reachable, key=lambda total: (abs(total - development_target), total > development_target, total))
    dev_projects = set(reachable[best_total])
    development = [pair for pair in pairs if (pair.project or pair.pair_id) in dev_projects]
    test = [pair for pair in pairs if (pair.project or pair.pair_id) not in dev_projects]
    return development, test


def stratified_subset(pairs: list[PairSample], size: int, seed: int) -> list[PairSample]:
    if size <= 0:
        return []
    if size >= len(pairs):
        return list(pairs)
    return balanced_sample(pairs, size, max_per_project=max(size, 1), seed=seed)


def dataset_summary(pairs: list[PairSample]) -> dict[str, Any]:
    cwes = Counter(cwe for pair in pairs for cwe in pair.cwe_ids)
    projects = Counter(pair.project or "unknown" for pair in pairs)
    languages = Counter(pair.language for pair in pairs)
    line_counts = [len(pair.vulnerable_code.splitlines()) for pair in pairs]
    return {
        "pairs": len(pairs),
        "versions": len(pairs) * 2,
        "projects": len(projects),
        "languages": dict(languages),
        "unique_cwes": len(cwes),
        "top_cwes": cwes.most_common(20),
        "median_vulnerable_lines": float(_median(line_counts)),
        "pairs_with_patch_proxy": sum(bool(pair.gold_vulnerable_lines) for pair in pairs),
        "max_pairs_per_project": max(projects.values(), default=0),
    }


def _median(values: list[int]) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return float(ordered[middle])
    return (ordered[middle - 1] + ordered[middle]) / 2.0


def prepare_dataset(config: DatasetConfig) -> dict[str, Any]:
    name = config.name.lower()
    if name == "secvuleval":
        raw_pairs = load_secvuleval(config)
    elif name == "primevul":
        raw_pairs = load_primevul(config)
    elif name == "pyvul":
        raw_pairs = load_pyvul(config)
    else:
        raise ValueError(f"Unsupported dataset: {config.name}")
    raw_count = len(raw_pairs)
    filtered = [pair for pair in deduplicate_pairs(raw_pairs) if _valid_pair(pair, config)]
    selected = balanced_sample(filtered, config.max_pairs, config.max_per_project, config.seed)
    development, test = project_disjoint_split(selected, config.development_pairs, config.seed)
    annotation = stratified_subset(test, config.annotation_pairs, config.seed + 1)
    faults = stratified_subset(test, config.fault_pairs, config.seed + 2)
    cross_model = stratified_subset(test, config.cross_model_pairs, config.seed + 3)
    stability = stratified_subset(test, config.stability_pairs, config.seed + 4)

    output = ensure_dir(config.output_dir)
    files = {
        "all_selected_pairs.jsonl": selected,
        "development_pairs.jsonl": development,
        "test_pairs.jsonl": test,
        "annotation_pairs.jsonl": annotation,
        "fault_pairs.jsonl": faults,
        "cross_model_pairs.jsonl": cross_model,
        "stability_pairs.jsonl": stability,
    }
    for filename, values in files.items():
        write_jsonl(output / filename, [pair.model_dump(mode="json") for pair in values])

    dev_projects = {pair.project for pair in development if pair.project}
    test_projects = {pair.project for pair in test if pair.project}
    manifest = {
        "dataset": config.name,
        "configuration": config.model_dump(mode="json"),
        "raw_pairs": raw_count,
        "filtered_pairs": len(filtered),
        "selected": dataset_summary(selected),
        "development": dataset_summary(development),
        "test": dataset_summary(test),
        "annotation": dataset_summary(annotation),
        "fault": dataset_summary(faults),
        "cross_model": dataset_summary(cross_model),
        "stability": dataset_summary(stability),
        "project_overlap_dev_test": sorted(dev_projects.intersection(test_projects)),
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def load_pairs(path: str | Path) -> list[PairSample]:
    return [PairSample.model_validate(row) for row in read_jsonl(path)]
