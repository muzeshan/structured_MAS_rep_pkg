# Artifact Evaluation Notes

## Claims supported by included files

- Clean aggregate RQ1 metrics and per-record decisions
- Structured RQ2 lineage counts
- Complete corrected RQ3 raw outputs and injected handoffs
- Statistical recomputation and integrity checks
- Exact paper source

## Suggested evaluator sequence

```bash
pip install -r environment/requirements-analysis.txt
python scripts/verify_artifact.py
python scripts/analyze_results.py --verify
pytest -q tests/test_replication_results.py
```

Expected terminal message: `All artifact verification checks passed.`

## Hardware

Result verification is CPU-only. Generation requires a CUDA GPU capable of loading the pinned 3B model in 4-bit mode. The reported runs used Google Colab T4-class hardware.
