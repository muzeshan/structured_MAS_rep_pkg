# Reproducibility Guide

## Levels of reproduction

### Level A — Verify reported results (about one minute)

```bash
pip install -r environment/requirements-analysis.txt
python scripts/analyze_results.py --verify
```

This verifies file counts, clean accuracy, free-form/structured agreement, exact McNemar counts, RQ2 lineage totals, and the key corrected RQ3 propagation rates.

### Level B — Re-run corrected RQ3 (GPU; roughly 2–3 hours on the original Colab T4 setup)

```bash
pip install -e '.[test]'
python scripts/run_rq3_corrected.py
```

The included manifest fixes the upstream cases and injected handoffs. Only the downstream critique/refutation and adjudication calls are regenerated.

### Level C — Re-run clean RQ1/RQ2 generation (GPU; roughly four hours on the original Colab T4 setup)

1. Prepare SecVulEval with `configs/prepare_secvuleval.yaml`.
2. Confirm the prepared development checksum.
3. Apply `scripts/filter_eligible_pairs.py`.
4. Run preflight.
5. Run `vulhandoff run --config configs/development_frozen_v3_qwen3b.yaml`.
6. Do not modify prompts, token ceilings, model revision, or decoding settings.

## Frozen design

- 29 eligible vulnerable/fixed pairs
- three workflow conditions
- one deterministic repetition
- same model and code context
- three calls per workflow
- output ceilings 340/220/480
- final JSON schema shared across conditions
- final parse failure defined as absence of a valid final report
- upstream parse errors recorded separately

## Corrected RQ3 faults

- **Verdict inversion:** replace the upstream verdict while retaining claim content.
- **Evidence deletion:** retain the verdict but remove every supporting claim and span.
- **Evidence corruption:** replace support with a standardized high-confidence false CWE-787 claim and an out-of-range span.

The previous instruction-prepending implementation is not included as evidence for the paper. The `results/rq3/raw/` directory contains only the corrected controlled comparison.

## Integrity checks

```bash
sha256sum -c SHA256SUMS.txt
python scripts/verify_artifact.py
pytest -q
```
