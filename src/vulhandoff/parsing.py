from __future__ import annotations

import json
import re
from typing import Any, TypeVar

from pydantic import BaseModel, ValidationError

from vulhandoff.models import (
    AnalysisHandoff,
    EvidenceClaim,
    FinalReport,
    LineSpan,
    RefutationHandoff,
    Verdict,
    normalize_cwe_list,
)

T = TypeVar("T", bound=BaseModel)


def extract_json_object(text: str) -> str:
    stripped = text.strip()
    stripped = re.sub(r"^```(?:json)?\s*", "", stripped, flags=re.I)
    stripped = re.sub(r"\s*```$", "", stripped)
    start = stripped.find("{")
    if start < 0:
        raise ValueError("No JSON object found")
    depth = 0
    in_string = False
    escaped = False
    for index in range(start, len(stripped)):
        char = stripped[index]
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return stripped[start : index + 1]
    raise ValueError("Unclosed JSON object")


def parse_model(text: str, model: type[T]) -> tuple[T | None, str | None]:
    try:
        candidate = extract_json_object(text)
        try:
            payload = json.loads(candidate)
        except json.JSONDecodeError:
            from json_repair import repair_json

            payload = json.loads(repair_json(candidate))
        return model.model_validate(payload), None
    except (ValueError, ValidationError, TypeError, json.JSONDecodeError) as exc:
        return None, str(exc)


def parse_analysis(text: str) -> tuple[AnalysisHandoff | None, str | None]:
    return parse_model(text, AnalysisHandoff)


def parse_refutation(text: str) -> tuple[RefutationHandoff | None, str | None]:
    return parse_model(text, RefutationHandoff)


def parse_final(text: str) -> tuple[FinalReport | None, str | None]:
    """Strictly parse a final report.

    No keyword-based rescue is used. A malformed final answer is an observable system failure
    and must remain an abstention/error in the final denominator.
    """
    return parse_model(text, FinalReport)


_CITATION_PATTERNS = [
    re.compile(r"\[\s*L?0*(\d+)\s*(?:[-–:]\s*L?0*(\d+))?\s*\]", re.I),
    re.compile(r"\bline(?:s)?\s+L?0*(\d+)\s*(?:[-–]|to)\s*L?0*(\d+)\b", re.I),
    re.compile(r"\bline\s+L?0*(\d+)\b", re.I),
    re.compile(r"\bL0*(\d+)\s*[-–:]\s*L0*(\d+)\b", re.I),
]


def extract_line_spans(text: str, max_line: int | None = None) -> list[LineSpan]:
    result: list[LineSpan] = []
    seen: set[tuple[int, int]] = set()
    for pattern in _CITATION_PATTERNS:
        for match in pattern.finditer(text):
            start = int(match.group(1))
            end_group = match.group(2) if (match.lastindex or 0) >= 2 else None
            end = int(end_group or start)
            if end < start:
                start, end = end, start
            if max_line is not None:
                if start > max_line:
                    continue
                end = min(end, max_line)
            if start < 1:
                continue
            key = (start, end)
            if key in seen:
                continue
            seen.add(key)
            result.append(LineSpan(start_line=start, end_line=end))
    return result


def infer_verdict(text: str) -> Verdict:
    matches = re.findall(
        r"(?:TENTATIVE_VERDICT|FINAL_VERDICT|VERDICT)\s*:\s*"
        r"(vulnerable|not[_ -]?vulnerable|uncertain)",
        text,
        flags=re.I,
    )
    if not matches:
        return Verdict.UNCERTAIN
    value = matches[-1].lower().replace(" ", "_").replace("-", "_")
    return Verdict(value)


def infer_claim_type(text: str) -> str:
    lowered = text.lower()
    categories = [
        ("command_injection", ["command injection", "shell command", "system(", "popen"]),
        ("memory_safety", ["buffer overflow", "out-of-bounds", "out of bounds", "strcpy", "use-after-free"]),
        ("path_traversal", ["path traversal", "directory traversal", "../"]),
        ("sql_injection", ["sql injection", "query concatenation"]),
        ("authentication", ["authentication", "authorization", "access control"]),
        ("integer_error", ["integer overflow", "integer underflow", "off-by-one"]),
        ("race_condition", ["race condition", "data race", "toctou"]),
        ("deserialization", ["deserialization", "pickle", "unserialize"]),
        ("input_validation", ["validation", "sanitization", "unchecked input"]),
    ]
    for name, needles in categories:
        if any(needle in lowered for needle in needles):
            return name
    return "generic"


def normalize_freeform_handoff(text: str, max_line: int | None = None) -> AnalysisHandoff:
    sentences = re.split(r"(?<=[.!?])\s+|\n+", text.strip())
    claims: list[EvidenceClaim] = []
    for index, sentence in enumerate(sentences, start=1):
        spans = extract_line_spans(sentence, max_line=max_line)
        cwes = normalize_cwe_list(sentence)
        if not spans and not cwes:
            continue
        claims.append(
            EvidenceClaim(
                claim_id=f"FF{index}",
                claim_type=infer_claim_type(sentence),
                statement=sentence.strip()[:1200],
                spans=spans,
                cwes=cwes,
                confidence=0.5,
            )
        )
    return AnalysisHandoff(
        tentative_verdict=infer_verdict(text),
        claims=claims,
        missing_information=[],
        summary=text[:1800],
    )
