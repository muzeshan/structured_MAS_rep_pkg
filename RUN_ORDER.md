# Run Order

## Verify the published results

```bash
pip install -r environment/requirements-analysis.txt
python scripts/verify_artifact.py
python scripts/analyze_results.py --verify
```

## Run software tests

```bash
pip install -e '.[test]'
pytest -q
```

## Re-run clean RQ1/RQ2 generation

```bash
vulhandoff prepare --config configs/prepare_secvuleval.yaml
python scripts/filter_eligible_pairs.py \
  data/prepared/secvuleval/development_pairs.jsonl \
  data/prepared/secvuleval/development_pairs_eligible.jsonl
vulhandoff preflight --config configs/development_frozen_v3_qwen3b.yaml
vulhandoff run --config configs/development_frozen_v3_qwen3b.yaml
```

## Re-run corrected RQ3

```bash
python scripts/run_rq3_corrected.py
```

## Compile the paper

```bash
cd paper
latexmk -pdf main.tex
```
