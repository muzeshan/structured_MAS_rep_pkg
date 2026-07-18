# Results and Manuscript Audit Checklist

## Data integrity

- [ ] Immutable dataset revision is reported.
- [ ] Pairing logic is documented and manually audited.
- [ ] Vulnerable and fixed code differ.
- [ ] Exact duplicates are removed before splitting.
- [ ] Related project examples do not cross development/test partitions.
- [ ] Dataset exclusions and final counts reconcile across text, tables, and artifact.
- [ ] CWE and project distributions are reported.
- [ ] The fixed counterpart is described as target-fixed, not globally vulnerability-free.

## Leakage controls

- [ ] Prompts contain no gold label, CVE ID, CWE ID, project identity, file path, commit message, advisory, or patch.
- [ ] Test examples were never used in few-shot prompts or prompt tuning.
- [ ] No dataset labels are inferred from filenames or metadata.
- [ ] Model contamination/memorization is discussed as a threat.

## Experimental fairness

- [ ] Same base model revision across primary systems.
- [ ] Same input code and maximum context.
- [ ] Same number of model calls.
- [ ] Same per-stage output ceilings.
- [ ] Same decoding configuration.
- [ ] Tool access is identical, or differences are explicitly isolated.
- [ ] Actual token and latency use are reported rather than assumed equal.
- [ ] Configuration hashes and protocol hash are archived.

## Output handling

- [ ] Malformed final JSON counts as an abstention/error.
- [ ] No keyword rescue, manual correction, or cherry-picked rerun is applied to final outputs.
- [ ] Cache/resume logic does not duplicate records.
- [ ] Every expected case/system/repetition is present.
- [ ] Parse-failure rates are shown.
- [ ] Raw outputs and structured records are archived.

## RQ1

- [ ] Pair-correct rate is primary.
- [ ] Abstentions count as incorrect in primary estimates.
- [ ] Coverage and selective accuracy are also reported.
- [ ] Fixed-version false-positive rate is visible.
- [ ] Pair error categories are shown.
- [ ] Localization is explicitly called a patch-overlap proxy.
- [ ] Results include confidence intervals.
- [ ] Paired tests use vulnerability pair as the unit.
- [ ] Multiple comparisons are corrected.
- [ ] Effect sizes are discussed, not only p-values.

## RQ2

- [ ] Automatic proxy metrics are not presented as semantic ground truth.
- [ ] Two independent annotators rated a frozen subset.
- [ ] The private key was hidden during annotation.
- [ ] Raw agreement and Cohen's kappa are reported before adjudication.
- [ ] Adjudication procedure is reported.
- [ ] Claims distinguish omission, distortion, invention, repair, and harm.
- [ ] System-format visibility is acknowledged as a blinding limitation.
- [ ] Representative cases are selected by predeclared rules, not rhetorical convenience.

## RQ3

- [ ] Fault definitions and eligibility are frozen.
- [ ] Identical fault instances are paired across handoff modes.
- [ ] Each fault family is reported separately.
- [ ] Propagation, repair, containment, and evidence-unresolved outcomes are distinguished.
- [ ] The amplification measure is labeled as a proxy where automatically inferred.
- [ ] `false_guard` is excluded unless manually validated per case.
- [ ] Paired tests use fault instance as the unit.

## Stability and external validity

- [ ] Stochastic repetitions are reported on a predeclared subset.
- [ ] Cross-model replication uses the same frozen subset and prompts.
- [ ] Decoding differences between deterministic primary and stochastic stability runs are explicit.
- [ ] Conclusions are bounded to the evaluated datasets, models, prompts, and role organization.

## Writing and claims

- [ ] No claim says multi-agent systems are universally superior.
- [ ] No “first” claim appears without a defensible search protocol.
- [ ] The paper is positioned as a handoff/evidence study, not a new state-of-the-art detector.
- [ ] LAMPS and the rejected Bandit-CWE study are transparently distinguished.
- [ ] Every abstract/result/conclusion claim maps to a generated table or manual analysis.
- [ ] Explanations of why a system performs better are framed as evidence-backed or speculative.
- [ ] Limitations include dataset noise, incomplete context, patch proxies, annotation subjectivity, and model contamination.
- [ ] All table values are generated from scripts.
- [ ] Numbers reconcile to the final manifest.

## Reproducibility package

- [ ] Source code and license are included.
- [ ] Exact YAML configurations are included.
- [ ] Model and dataset revisions are pinned.
- [ ] Split files or stable identifiers are included where licensing permits.
- [ ] Raw records, prompts, and result scripts are archived.
- [ ] README commands reproduce every paper table and figure.
- [ ] Automated tests pass in a clean environment.
- [ ] No live exploit, credential, or unsafe execution artifact is released.
