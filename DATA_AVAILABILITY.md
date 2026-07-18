# Data Availability and Licensing

## SecVulEval

The clean experiment uses paired C/C++ functions prepared from SecVulEval. This repository provides the preparation adapter and configuration but does not claim ownership of SecVulEval or the underlying project code.

Prepared-file checksums from the study:

- development pairs: `7d206a52190182a48c9a2fdf6dfd95d017c66f4d017a1ba77d9e6eb335dcaecf`
- test pairs: `57a7324a6e1b35ee170efbb12c2e6160c23e0e1a11f0da5ed118aa9499324857`

One development pair was excluded under the frozen function-only eligibility rule:

- `secvuleval::15308::e753a7013efd`
- category: `invalid_for_function_only`
- reason: the CWE-59 behavior was implemented in unseen callees rather than in the supplied function body.

## Included results

- Clean-run record-level derived CSVs are under `results/clean/`.
- Corrected RQ3 raw records and exact injected handoffs are under `results/rq3/raw/`.
- The RQ3 manifest contains source snippets needed to reproduce the downstream experiment. Before making a public archival deposit, verify that redistribution is compatible with the relevant benchmark and upstream-project licenses.

## Privacy

The artifact contains no human-subject data and no credentials. Inspect all configuration files before publication to ensure that local paths, tokens, and account identifiers have not been introduced.
