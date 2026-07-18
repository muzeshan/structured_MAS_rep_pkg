from __future__ import annotations

import json
import sqlite3
import threading
import time
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from vulhandoff.config import ModelConfig
from vulhandoff.models import GenerationResult
from vulhandoff.utils import chunks, ensure_dir, seed_everything, stable_hash


class GenerationCache:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        ensure_dir(self.path.parent)
        self.lock = threading.Lock()
        with self._connect() as connection:
            connection.execute(
                """CREATE TABLE IF NOT EXISTS generations (
                    cache_key TEXT PRIMARY KEY,
                    payload TEXT NOT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )"""
            )
            connection.commit()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path, timeout=60)

    def get(self, key: str) -> GenerationResult | None:
        with self.lock, self._connect() as connection:
            row = connection.execute(
                "SELECT payload FROM generations WHERE cache_key = ?", (key,)
            ).fetchone()
        if row is None:
            return None
        result = GenerationResult.model_validate(json.loads(row[0]))
        result.cached = True
        return result

    def put(self, key: str, result: GenerationResult) -> None:
        payload = json.dumps(result.model_dump(mode="json"), ensure_ascii=False)
        with self.lock, self._connect() as connection:
            connection.execute(
                "INSERT OR REPLACE INTO generations(cache_key, payload) VALUES (?, ?)",
                (key, payload),
            )
            connection.commit()


class ChatBackend(ABC):
    def __init__(
        self,
        model_id: str,
        revision: str | None,
        cache: GenerationCache | None,
    ):
        self.model_id = model_id
        self.revision = revision
        self.cache = cache

    def generate_batch(
        self,
        conversations: list[list[dict[str, str]]],
        *,
        max_new_tokens: int,
        temperature: float,
        top_p: float,
        do_sample: bool,
        seed: int,
    ) -> list[GenerationResult]:
        parameters = {
            "max_new_tokens": max_new_tokens,
            "temperature": temperature,
            "top_p": top_p,
            "do_sample": do_sample,
            "seed": seed,
        }
        results: list[GenerationResult | None] = [None] * len(conversations)
        missing_indices: list[int] = []
        missing_conversations: list[list[dict[str, str]]] = []
        missing_keys: list[str] = []
        for index, messages in enumerate(conversations):
            key = stable_hash(
                self.model_id,
                self.revision,
                messages,
                parameters,
                length=64,
            )
            cached = self.cache.get(key) if self.cache else None
            if cached is not None:
                results[index] = cached
            else:
                missing_indices.append(index)
                missing_conversations.append(messages)
                missing_keys.append(key)
        if missing_conversations:
            generated = self._generate_uncached(
                missing_conversations,
                max_new_tokens=max_new_tokens,
                temperature=temperature,
                top_p=top_p,
                do_sample=do_sample,
                seed=seed,
            )
            if len(generated) != len(missing_conversations):
                raise RuntimeError("Generation backend returned an unexpected number of outputs")
            for index, key, result in zip(missing_indices, missing_keys, generated):
                results[index] = result
                if self.cache:
                    self.cache.put(key, result)
        return [result or GenerationResult(text="", error="missing output") for result in results]

    @abstractmethod
    def _generate_uncached(
        self,
        conversations: list[list[dict[str, str]]],
        *,
        max_new_tokens: int,
        temperature: float,
        top_p: float,
        do_sample: bool,
        seed: int,
    ) -> list[GenerationResult]:
        raise NotImplementedError


class TransformersBackend(ChatBackend):
    def __init__(self, config: ModelConfig, cache: GenerationCache | None):
        super().__init__(config.model_id, config.revision, cache)
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig

        self.torch = torch
        self.batch_size = config.batch_size
        self.max_input_tokens = config.max_input_tokens
        self.tokenizer = AutoTokenizer.from_pretrained(
            config.model_id,
            revision=config.revision,
            trust_remote_code=config.trust_remote_code,
            use_fast=True,
        )
        if self.tokenizer.pad_token_id is None:
            self.tokenizer.pad_token = self.tokenizer.eos_token
        self.tokenizer.padding_side = "left"

        if config.load_in_4bit and not torch.cuda.is_available():
            raise RuntimeError("4-bit loading requires a CUDA runtime; disable load_in_4bit for CPU tests")
        kwargs: dict[str, Any] = {
            "revision": config.revision,
            "trust_remote_code": config.trust_remote_code,
            "low_cpu_mem_usage": True,
        }
        if torch.cuda.is_available():
            kwargs["device_map"] = "auto"
        if config.load_in_4bit:
            major, _ = torch.cuda.get_device_capability(0)
            compute_dtype = torch.bfloat16 if major >= 8 else torch.float16
            kwargs["quantization_config"] = BitsAndBytesConfig(
                load_in_4bit=True,
                bnb_4bit_quant_type="nf4",
                bnb_4bit_compute_dtype=compute_dtype,
                bnb_4bit_use_double_quant=True,
            )
        elif config.dtype == "auto":
            kwargs["torch_dtype"] = "auto"
        else:
            kwargs["torch_dtype"] = getattr(torch, config.dtype)
        self.model = AutoModelForCausalLM.from_pretrained(config.model_id, **kwargs)
        self.model.eval()

    def _render(self, messages: list[dict[str, str]]) -> str:
        if hasattr(self.tokenizer, "apply_chat_template"):
            return self.tokenizer.apply_chat_template(
                messages,
                tokenize=False,
                add_generation_prompt=True,
            )
        return "\n".join(f"{item['role'].upper()}: {item['content']}" for item in messages) + "\nASSISTANT:"

    def _generate_uncached(
        self,
        conversations: list[list[dict[str, str]]],
        *,
        max_new_tokens: int,
        temperature: float,
        top_p: float,
        do_sample: bool,
        seed: int,
    ) -> list[GenerationResult]:
        seed_everything(seed)
        rendered = [self._render(messages) for messages in conversations]
        token_lengths = [
            len(self.tokenizer(text, add_special_tokens=False)["input_ids"])
            for text in rendered
        ]
        too_long = [length for length in token_lengths if length > self.max_input_tokens]
        if too_long:
            raise ValueError(
                f"{len(too_long)} prompts exceed max_input_tokens={self.max_input_tokens}; "
                f"maximum rendered length was {max(too_long)}. The artifact refuses silent truncation. "
                "Reduce the frozen dataset code-length limit before the final run."
            )
        results: list[GenerationResult] = []
        for prompt_batch in chunks(rendered, self.batch_size):
            encoded = self.tokenizer(
                prompt_batch,
                return_tensors="pt",
                padding=True,
                truncation=False,
            )
            device = next(self.model.parameters()).device
            encoded = {key: value.to(device) for key, value in encoded.items()}
            input_lengths = encoded["attention_mask"].sum(dim=1).tolist()
            generation_kwargs: dict[str, Any] = {
                "max_new_tokens": max_new_tokens,
                "do_sample": do_sample,
                "pad_token_id": self.tokenizer.pad_token_id,
                "eos_token_id": self.tokenizer.eos_token_id,
                "use_cache": True,
            }
            if do_sample:
                generation_kwargs.update(
                    temperature=max(temperature, 1e-5),
                    top_p=top_p,
                )
            start = time.perf_counter()
            try:
                with self.torch.inference_mode():
                    generated = self.model.generate(**encoded, **generation_kwargs)
            except RuntimeError as exc:
                if "out of memory" in str(exc).lower():
                    raise RuntimeError(
                        "CUDA out of memory. Reduce model.batch_size before freezing/rerunning the protocol."
                    ) from exc
                raise
            elapsed = time.perf_counter() - start
            padded_input_length = encoded["input_ids"].shape[1]
            for row_index in range(generated.shape[0]):
                new_tokens = generated[row_index, padded_input_length:]
                text = self.tokenizer.decode(new_tokens, skip_special_tokens=True).strip()
                # Re-tokenize the decoded text rather than counting the padded generation
                # tensor. In batched generation, shorter sequences are padded to the longest
                # completion and would otherwise receive inflated token counts.
                completion_count = len(
                    self.tokenizer(text, add_special_tokens=False)["input_ids"]
                )
                results.append(
                    GenerationResult(
                        text=text,
                        prompt_tokens=int(input_lengths[row_index]),
                        completion_tokens=completion_count,
                        latency_seconds=elapsed / max(len(prompt_batch), 1),
                        finish_reason=(
                            "length" if completion_count >= max_new_tokens else "stop"
                        ),
                    )
                )
        return results


class VLLMBackend(ChatBackend):
    def __init__(self, config: ModelConfig, cache: GenerationCache | None):
        super().__init__(config.model_id, config.revision, cache)
        from transformers import AutoTokenizer
        from vllm import LLM

        self.tokenizer = AutoTokenizer.from_pretrained(
            config.model_id,
            revision=config.revision,
            trust_remote_code=config.trust_remote_code,
        )
        self.max_input_tokens = config.max_input_tokens
        self.llm = LLM(
            model=config.model_id,
            revision=config.revision,
            dtype=config.dtype,
            trust_remote_code=config.trust_remote_code,
            max_model_len=config.max_input_tokens + 1024,
            gpu_memory_utilization=0.90,
        )

    def _render(self, messages: list[dict[str, str]]) -> str:
        return self.tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)

    def _generate_uncached(
        self,
        conversations: list[list[dict[str, str]]],
        *,
        max_new_tokens: int,
        temperature: float,
        top_p: float,
        do_sample: bool,
        seed: int,
    ) -> list[GenerationResult]:
        from vllm import SamplingParams

        prompts = [self._render(messages) for messages in conversations]
        lengths = [len(self.tokenizer(prompt, add_special_tokens=False)["input_ids"]) for prompt in prompts]
        if any(length > self.max_input_tokens for length in lengths):
            raise ValueError("A rendered prompt exceeds max_input_tokens; silent truncation is disabled")
        parameters = SamplingParams(
            temperature=temperature if do_sample else 0.0,
            top_p=top_p,
            max_tokens=max_new_tokens,
            seed=seed,
        )
        start = time.perf_counter()
        generations = self.llm.generate(prompts, parameters, use_tqdm=True)
        elapsed = time.perf_counter() - start
        results: list[GenerationResult] = []
        for generation in generations:
            output = generation.outputs[0]
            results.append(
                GenerationResult(
                    text=output.text.strip(),
                    prompt_tokens=len(generation.prompt_token_ids),
                    completion_tokens=len(output.token_ids),
                    latency_seconds=elapsed / max(len(prompts), 1),
                    finish_reason=str(output.finish_reason),
                )
            )
        return results


class MockBackend(ChatBackend):
    """Deterministic backend for tests only; never use its outputs in a paper."""

    @staticmethod
    def _code(prompt: str) -> str:
        marker = "Numbered code:\n"
        return prompt.rsplit(marker, 1)[-1] if marker in prompt else prompt

    @staticmethod
    def _is_vulnerable(code: str) -> bool:
        return any(token in code for token in ["strcpy(", "gets(", "system(", "eval("])

    def _generate_uncached(
        self,
        conversations: list[list[dict[str, str]]],
        *,
        max_new_tokens: int,
        temperature: float,
        top_p: float,
        do_sample: bool,
        seed: int,
    ) -> list[GenerationResult]:
        results: list[GenerationResult] = []
        for messages in conversations:
            prompt = messages[-1]["content"]
            vulnerable = self._is_vulnerable(self._code(prompt))
            verdict = "vulnerable" if vulnerable else "not_vulnerable"
            if "structured ANALYST" in prompt:
                payload = {
                    "tentative_verdict": verdict,
                    "claims": [
                        {
                            "claim_id": "C1",
                            "claim_type": "memory_or_command_safety",
                            "statement": "Unsafe operation is present at the cited line",
                            "spans": [{"start_line": 2, "end_line": 2}],
                            "cwes": ["CWE-120"],
                            "source": "function argument",
                            "sink": "unsafe operation",
                            "trigger_or_precondition": "attacker controls input",
                            "guard_status": "absent",
                            "consequence": "memory corruption or command execution",
                            "confidence": 0.8,
                            "support_ids": [],
                        }
                    ] if vulnerable else [],
                    "missing_information": [],
                    "summary": "Mock structured analysis",
                }
                text = json.dumps(payload)
            elif "structured REFUTER" in prompt:
                payload = {
                    "overall_assessment": verdict,
                    "decisions": [
                        {
                            "claim_id": "C1",
                            "status": "supported",
                            "rationale": "The cited operation is visible",
                            "counterevidence_spans": [],
                            "corrected_claim": None,
                        }
                    ] if vulnerable else [],
                    "new_claims": [],
                    "unresolved_questions": [],
                    "summary": "Mock structured refutation",
                }
                text = json.dumps(payload)
            elif "final ADJUDICATOR" in prompt:
                payload = {
                    "verdict": verdict,
                    "confidence": 0.8,
                    "cwes": ["CWE-120"] if vulnerable else [],
                    "findings": [
                        {
                            "finding_id": "F1",
                            "statement": "Unsafe operation",
                            "spans": [{"start_line": 2, "end_line": 2}],
                            "cwes": ["CWE-120"],
                            "trigger_or_precondition": "attacker controls input",
                            "guard_assessment": "no effective guard",
                            "confidence": 0.8,
                            "source_claim_ids": ["C1"],
                        }
                    ] if vulnerable else [],
                    "rejected_claim_ids": [],
                    "rationale": "Mock final decision",
                    "uncertainty_reason": None,
                }
                text = json.dumps(payload)
            else:
                text = (
                    f"The code is assessed as {verdict}. Evidence [L0002-L0002].\n"
                    f"TENTATIVE_VERDICT: {verdict}"
                )
            results.append(
                GenerationResult(
                    text=text,
                    prompt_tokens=max(1, len(prompt.split())),
                    completion_tokens=max(1, len(text.split())),
                    latency_seconds=0.001,
                    finish_reason="stop",
                )
            )
        return results


def create_backend(config: ModelConfig) -> ChatBackend:
    cache = GenerationCache(config.cache_db) if config.cache_db else None
    backend = config.backend.lower()
    if backend == "mock":
        return MockBackend(config.model_id, config.revision, cache)
    if backend == "transformers":
        return TransformersBackend(config, cache)
    if backend == "vllm":
        return VLLMBackend(config, cache)
    raise ValueError(f"Unknown model backend: {config.backend}")
