from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, model_validator


class DatasetConfig(BaseModel):
    name: str = "secvuleval"
    input_path: str | None = None
    hf_dataset_id: str = "arag0rn/SecVulEval"
    hf_revision: str | None = None
    hf_split: str = "train"
    output_dir: str = "data/prepared/secvuleval"
    max_pairs: int | None = 280
    development_pairs: int = 40
    annotation_pairs: int = 60
    fault_pairs: int = 80
    cross_model_pairs: int = 60
    stability_pairs: int = 60
    max_per_project: int = 8
    min_code_lines: int = 4
    max_code_lines: int = 300
    max_code_chars: int = 12000
    seed: int = 20260712


class ModelConfig(BaseModel):
    backend: str = "transformers"
    model_id: str = "Qwen/Qwen2.5-Coder-7B-Instruct"
    revision: str | None = None
    dtype: str = "auto"
    load_in_4bit: bool = True
    max_input_tokens: int = 8192
    batch_size: int = 4
    temperature: float = 0.0
    top_p: float = 1.0
    do_sample: bool = False
    trust_remote_code: bool = False
    cache_db: str | None = "cache/generations.sqlite"


class StageBudget(BaseModel):
    analysis: int = 420
    critique: int = 420
    adjudication: int = 520


class ExperimentConfig(BaseModel):
    prepared_pairs: str = "data/prepared/secvuleval/test_pairs.jsonl"
    output_dir: str = "outputs/main_qwen7b"
    systems: list[str] = Field(
        default_factory=lambda: ["self_refine", "freeform_mas", "structured_mas"]
    )
    repetitions: int = 1
    base_seed: int = 20260712
    shard_index: int = 0
    num_shards: int = 1
    overwrite: bool = False
    budget: StageBudget = Field(default_factory=StageBudget)
    model: ModelConfig = Field(default_factory=ModelConfig)

    @model_validator(mode="after")
    def validate_shard(self) -> "ExperimentConfig":
        if self.num_shards < 1:
            raise ValueError("num_shards must be >= 1")
        if not 0 <= self.shard_index < self.num_shards:
            raise ValueError("shard_index must satisfy 0 <= shard_index < num_shards")
        return self


class FaultConfig(BaseModel):
    prepared_pairs: str = "data/prepared/secvuleval/fault_pairs.jsonl"
    output_dir: str = "outputs/faults_qwen7b"
    fault_types: list[str] = Field(default_factory=lambda: ["label_flip", "wrong_cwe", "wrong_location"])
    handoff_modes: list[str] = Field(default_factory=lambda: ["freeform", "structured"])
    repetitions: int = 1
    base_seed: int = 20260712
    shard_index: int = 0
    num_shards: int = 1
    overwrite: bool = False
    budget: StageBudget = Field(default_factory=StageBudget)
    model: ModelConfig = Field(default_factory=ModelConfig)

    @model_validator(mode="after")
    def validate_shard(self) -> "FaultConfig":
        if self.num_shards < 1:
            raise ValueError("num_shards must be >= 1")
        if not 0 <= self.shard_index < self.num_shards:
            raise ValueError("shard_index must satisfy 0 <= shard_index < num_shards")
        return self


class AnalysisConfig(BaseModel):
    main_results: str = "outputs/main_qwen7b"
    fault_results: str | None = "outputs/faults_qwen7b"
    pairs_path: str = "data/prepared/secvuleval/test_pairs.jsonl"
    annotation_path: str | None = None
    output_dir: str = "results/qwen7b_primary"
    bootstrap_iterations: int = 2000
    seed: int = 20260712


def load_yaml(path: str | Path) -> dict[str, Any]:
    with Path(path).open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def _section(path: str | Path, key: str) -> dict[str, Any]:
    data = load_yaml(path)
    return data.get(key, data)


def load_dataset_config(path: str | Path) -> DatasetConfig:
    return DatasetConfig.model_validate(_section(path, "dataset"))


def load_experiment_config(path: str | Path) -> ExperimentConfig:
    return ExperimentConfig.model_validate(_section(path, "experiment"))


def load_fault_config(path: str | Path) -> FaultConfig:
    return FaultConfig.model_validate(_section(path, "faults"))


def load_analysis_config(path: str | Path) -> AnalysisConfig:
    return AnalysisConfig.model_validate(_section(path, "analysis"))
