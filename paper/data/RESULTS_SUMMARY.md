# Results summary used in the paper

## Clean run (29 pairs / 58 versions per system)

| System | Accuracy | Vulnerable recall | Fixed accuracy | FPR | Pair correctness | Mean completion tokens | Mean latency (s) |
|---|---:|---:|---:|---:|---:|---:|---:|
| Self-refinement | 48.3% | 79.3% | 17.2% | 82.8% | 10.3% | 708.8 | 62.2 |
| Free-form MAS | 51.7% | 96.6% | 6.9% | 93.1% | 6.9% | 714.9 | 62.6 |
| Structured MAS | 51.7% | 96.6% | 6.9% | 93.1% | 3.4% | 532.0 | 47.4 |

Cochran Q = 0.615, p = 0.735. Free-form versus structured predictions agree on 54/58 versions. Each system is uniquely correct twice among the four disagreements; exact McNemar p = 1.0.

## Structured lineage

- analyst claims: 56
- refuter decisions: 58
- final findings: 55
- traceable final source IDs: 55/55
- unsupported final source IDs: 0/55
- supported/refuted/corrected/uncertain decisions: 57/1/0/0
- parse failures: 0

## Corrected fault injection (30 versions per system/fault)

- final parse failures: 1/270
- downstream stage parse errors: 3/810 (two refuter fallbacks and one invalid final adjudication)

| Metric | Self | Free | Structured |
|---|---:|---:|---:|
| Verdict inversion: pre-fault verdict restored | 83.3% | 43.3% | 96.7% |
| Verdict inversion: injected verdict followed | 10.0% | 26.7% | 0.0% |
| Evidence deletion: final finding generated | 53.3% | 26.7% | 100.0% |
| Evidence deletion: span overlaps changed-line proxy | 26.7% | 13.3% | 50.0% |
| Evidence corruption: injected CWE-787 retained | 20.0% | 23.3% | 93.3% |
| Evidence corruption: exact invalid span copied | 10.0% | 10.0% | 33.3% |
