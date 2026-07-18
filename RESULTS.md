# Results at a Glance

## RQ1 — Effectiveness and efficiency

| System | Accuracy | Vulnerable recall | Fixed accuracy | FPR | Pair correctness | Mean completion tokens | Mean latency (s) |
|---|---:|---:|---:|---:|---:|---:|---:|
| Self-refinement | 48.3% | 79.3% | 17.2% | 82.8% | 10.3% | 708.8 | 62.2 |
| Free-form MAS | 51.7% | 96.6% | 6.9% | 93.1% | 6.9% | 714.9 | 62.6 |
| Structured MAS | 51.7% | 96.6% | 6.9% | 93.1% | 3.4% | 532.0 | 47.4 |

Free-form and structured predictions agreed on 54/58 versions. Each system was uniquely correct twice among the four disagreements; exact McNemar `p = 1.0`.

## RQ2 — Structured lineage

- 56 analyst claims
- 58 refuter decisions
- 55 final findings
- 55/55 traceable final source IDs
- 0 unsupported final source IDs
- decisions: 57 supported, 1 refuted, 0 corrected, 0 uncertain
- 0 structured stage parse failures

## RQ3 — Corrected fault injection

The raw package contains one invalid final adjudication and two structured refuter parse errors handled by the frozen fallback (269/270 valid final reports; 3/810 downstream stage parse errors).

| Metric | Self | Free | Structured |
|---|---:|---:|---:|
| Verdict inversion: pre-fault verdict restored | 83.3% | 43.3% | 96.7% |
| Verdict inversion: injected verdict followed | 10.0% | 26.7% | 0.0% |
| Evidence deletion: final finding generated | 53.3% | 26.7% | 100.0% |
| Evidence deletion: span overlaps changed-line proxy | 26.7% | 13.3% | 50.0% |
| Evidence corruption: injected CWE-787 retained | 20.0% | 23.3% | 93.3% |
| Evidence corruption: exact invalid span copied | 10.0% | 10.0% | 33.3% |

The structured workflow was highly stable against direct verdict inversion but highly susceptible to faithfully preserving corrupted semantic evidence.
