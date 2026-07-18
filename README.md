# Structured Evidence Handoffs in LLM Multi-Agent Vulnerability Analysis

Replication package for the MAS-GAIN 2026 paper:

> **Structured Evidence Handoffs in LLM Multi-Agent Vulnerability Analysis: Accuracy, Traceability, and Fault Propagation**

The artifact compares three matched three-call workflows on paired vulnerable/fixed C/C++ functions:

1. **Self-refinement** — one auditor performs analysis, critique, and adjudication.
2. **Free-form MAS** — analyst, refuter, and adjudicator exchange prose.
3. **Structured MAS** — the same roles exchange typed claim/evidence records.

All reported workflows use the same pinned model, code input, deterministic decoding, three calls, and stage ceilings. The treatment of interest is the representation of the inter-agent handoff.

## Published findings

- Free-form and structured MAS both achieved **51.7% version accuracy** on 29 vulnerable/fixed pairs; their predictions agreed on 54/58 versions and exact McNemar testing returned `p = 1.0`.
- Structured MAS reduced mean completion tokens by **25.6%** and mean latency by **24.2%** relative to free-form MAS.
- All 55 structured final claim references were traceable to analyst claims, but the refuter supported 57/58 upstream decisions.
- In the corrected 270-run fault experiment, structured MAS restored the pre-fault verdict in **96.7%** of verdict-inversion cases, yet retained an injected false CWE-787 in **93.3%** of evidence-corruption cases.

The central result is a trade-off: structured communication improved efficiency, lineage, and categorical verdict stability, but could preserve false evidence more faithfully when verification was weak.

## Artifact contents

```text
configs/                     Frozen experiment configuration
src/vulhandoff/              Dataset, prompt, inference, workflow, and parsing code
scripts/                     Clean-run helpers, corrected RQ3 runner, and analysis
results/clean/               Clean-run derived record and aggregate tables
results/rq3/raw/             270 raw corrected fault records and exact manifest
results/rq3/derived/         Derived fault-injection tables
results/verification/        Recomputed tables produced by analysis
paper/                       Complete Overleaf source and compiled PDF
notebooks/                   Replication walkthrough and legacy development notebook
data/metadata/               Dataset checksums, pair selection, and exclusion log
docs/                        Protocol and artifact documentation
tests/                       Software and result-verification tests
```

## One-command result verification

No GPU or model download is required to verify the paper's reported numbers.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r environment/requirements-analysis.txt
python scripts/verify_artifact.py
python scripts/analyze_results.py --verify
```

The analysis rewrites verification tables under `results/verification/` and recomputes RQ3 record-level tables under `results/rq3/derived/`.

## Software installation

For the full experiment harness:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[test]'
pytest -q
```

GPU generation was conducted with:

- model: `Qwen/Qwen2.5-Coder-3B-Instruct`
- revision: `488639f1ff808d1d3d0ba301aef8c11461451ec5`
- 4-bit loading: enabled
- deterministic decoding: `do_sample=false`, temperature `0`
- stage ceilings: analysis `340`, critique/refutation `220`, adjudication `480`
- base seed: `20260712`

## Reproducing the clean experiment

Prepare SecVulEval using the pinned adapter configuration:

```bash
vulhandoff prepare --config configs/prepare_secvuleval.yaml
python scripts/filter_eligible_pairs.py \
  data/prepared/secvuleval/development_pairs.jsonl \
  data/prepared/secvuleval/development_pairs_eligible.jsonl
vulhandoff preflight --config configs/development_frozen_v3_qwen3b.yaml
vulhandoff run --config configs/development_frozen_v3_qwen3b.yaml
```

Expected scale:

```text
29 pairs
58 versions
174 workflow records
522 generation calls
```

The prepared development/test checksums used during the study are recorded in `data/metadata/dataset_checksums.json`.

## Reproducing corrected RQ3

The exact corrected manifest is included, so the downstream fault experiment can be rerun without regenerating analyst outputs:

```bash
python scripts/run_rq3_corrected.py
```

Expected scale:

```text
15 pairs × 2 versions × 3 systems × 3 faults = 270 records
```

The script is resumable and skips already completed system/pair/version/fault combinations.

## Data availability note

The corrected RQ3 package includes raw stage-level JSONL records and the exact injected handoffs. The clean-run files available when this repository was assembled were the derived record-level and RQ2 tables, not the original 174 raw stage-level JSONL records. Thus:

- all published clean aggregate results can be recomputed from `results/clean/record_level_results.csv`;
- structured lineage counts can be recomputed from `results/clean/rq2_structured_handoffs.csv`;
- the complete clean generation can be rerun from the frozen code/configuration;
- the complete corrected RQ3 raw records are included.

See `DATA_AVAILABILITY.md` for dataset and redistribution details.

## Paper

The exact paper source is under `paper/`. Compile with:

```bash
cd paper
latexmk -pdf main.tex
```

## Citation

Use the metadata in `CITATION.cff`. A DOI can be added after archival release.

## License

Experiment code is released under the MIT License. Dataset records and third-party source-code snippets remain subject to their original licenses; see `DATA_AVAILABILITY.md`.
