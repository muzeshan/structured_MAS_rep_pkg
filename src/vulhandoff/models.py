from __future__ import annotations

import re
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator


def normalize_cwe_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        items = [value]
    elif isinstance(value, (list, tuple, set)):
        items = list(value)
    else:
        items = [value]
    result: list[str] = []
    for item in items:
        text = str(item).strip().upper().replace("_", "-")
        matches = re.findall(r"CWE\s*-?\s*(\d+)", text)
        if matches:
            for number in matches:
                cwe = f"CWE-{int(number)}"
                if cwe not in result:
                    result.append(cwe)
        elif text.isdigit():
            cwe = f"CWE-{int(text)}"
            if cwe not in result:
                result.append(cwe)
    return result


class Verdict(str, Enum):
    VULNERABLE = "vulnerable"
    NOT_VULNERABLE = "not_vulnerable"
    UNCERTAIN = "uncertain"


class GuardStatus(str, Enum):
    PRESENT_EFFECTIVE = "present_effective"
    PRESENT_INEFFECTIVE = "present_ineffective"
    ABSENT = "absent"
    UNKNOWN = "unknown"


class LineSpan(BaseModel):
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)

    @model_validator(mode="after")
    def check_order(self) -> "LineSpan":
        if self.end_line < self.start_line:
            raise ValueError("end_line must be >= start_line")
        return self

    def lines(self) -> set[int]:
        return set(range(self.start_line, self.end_line + 1))


class EvidenceClaim(BaseModel):
    claim_id: str
    claim_type: str = "generic"
    statement: str
    spans: list[LineSpan] = Field(default_factory=list)
    cwes: list[str] = Field(default_factory=list)
    source: str | None = None
    sink: str | None = None
    trigger_or_precondition: str | None = None
    guard_status: GuardStatus = GuardStatus.UNKNOWN
    consequence: str | None = None
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    support_ids: list[str] = Field(default_factory=list)

    @field_validator("cwes", mode="before")
    @classmethod
    def validate_cwes(cls, value: Any) -> list[str]:
        return normalize_cwe_list(value)


class AnalysisHandoff(BaseModel):
    tentative_verdict: Verdict
    claims: list[EvidenceClaim] = Field(default_factory=list)
    missing_information: list[str] = Field(default_factory=list)
    summary: str = ""


class ClaimDecision(BaseModel):
    claim_id: str
    status: Literal["supported", "refuted", "uncertain", "corrected"]
    rationale: str
    counterevidence_spans: list[LineSpan] = Field(default_factory=list)
    corrected_claim: EvidenceClaim | None = None


class RefutationHandoff(BaseModel):
    overall_assessment: Verdict
    decisions: list[ClaimDecision] = Field(default_factory=list)
    new_claims: list[EvidenceClaim] = Field(default_factory=list)
    unresolved_questions: list[str] = Field(default_factory=list)
    summary: str = ""


class FinalFinding(BaseModel):
    finding_id: str
    statement: str
    spans: list[LineSpan] = Field(default_factory=list)
    cwes: list[str] = Field(default_factory=list)
    trigger_or_precondition: str | None = None
    guard_assessment: str | None = None
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    source_claim_ids: list[str] = Field(default_factory=list)

    @field_validator("cwes", mode="before")
    @classmethod
    def validate_cwes(cls, value: Any) -> list[str]:
        return normalize_cwe_list(value)


class FinalReport(BaseModel):
    verdict: Verdict
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    cwes: list[str] = Field(default_factory=list)
    findings: list[FinalFinding] = Field(default_factory=list)
    rejected_claim_ids: list[str] = Field(default_factory=list)
    rationale: str = ""
    uncertainty_reason: str | None = None

    @field_validator("cwes", mode="before")
    @classmethod
    def validate_cwes(cls, value: Any) -> list[str]:
        return normalize_cwe_list(value)


class PairSample(BaseModel):
    pair_id: str
    dataset: str
    language: str
    project: str | None = None
    cve_ids: list[str] = Field(default_factory=list)
    cwe_ids: list[str] = Field(default_factory=list)
    file_path: str | None = None
    function_name: str | None = None
    vulnerable_code: str
    fixed_code: str
    gold_vulnerable_lines: list[int] = Field(default_factory=list)
    gold_fixed_lines: list[int] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("cwe_ids", mode="before")
    @classmethod
    def validate_cwe_ids(cls, value: Any) -> list[str]:
        return normalize_cwe_list(value)


class CaseSample(BaseModel):
    case_id: str
    pair_id: str
    dataset: str
    version: Literal["vulnerable", "fixed"]
    label: int = Field(ge=0, le=1)
    language: str
    code: str
    project: str | None = None
    cve_ids: list[str] = Field(default_factory=list)
    cwe_ids: list[str] = Field(default_factory=list)
    file_path: str | None = None
    function_name: str | None = None
    gold_lines: list[int] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("cwe_ids", mode="before")
    @classmethod
    def validate_cwe_ids(cls, value: Any) -> list[str]:
        return normalize_cwe_list(value)


class GenerationResult(BaseModel):
    text: str
    prompt_tokens: int = 0
    completion_tokens: int = 0
    latency_seconds: float = 0.0
    finish_reason: str | None = None
    cached: bool = False
    error: str | None = None


class StageRecord(BaseModel):
    stage: str
    raw_text: str
    parsed: dict[str, Any] | None = None
    parse_error: str | None = None
    prompt_tokens: int = 0
    completion_tokens: int = 0
    latency_seconds: float = 0.0


class ExperimentRecord(BaseModel):
    run_id: str
    system: str
    model: str
    model_revision: str | None = None
    repetition: int
    seed: int
    case: CaseSample
    stages: list[StageRecord] = Field(default_factory=list)
    final_report: FinalReport | None = None
    total_prompt_tokens: int = 0
    total_completion_tokens: int = 0
    total_latency_seconds: float = 0.0
    parse_failed: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)


class FaultSpec(BaseModel):
    fault_id: str
    case_id: str
    pair_id: str
    fault_type: Literal["label_flip", "wrong_cwe", "wrong_location", "false_guard"]
    gold_value: Any
    faulty_value: Any
    claim: EvidenceClaim
    faulty_verdict: Verdict
    metadata: dict[str, Any] = Field(default_factory=dict)


class FaultExperimentRecord(BaseModel):
    run_id: str
    handoff_mode: Literal["freeform", "structured"]
    model: str
    model_revision: str | None = None
    repetition: int
    seed: int
    case: CaseSample
    fault: FaultSpec
    stages: list[StageRecord] = Field(default_factory=list)
    final_report: FinalReport | None = None
    total_prompt_tokens: int = 0
    total_completion_tokens: int = 0
    total_latency_seconds: float = 0.0
    outcome: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
