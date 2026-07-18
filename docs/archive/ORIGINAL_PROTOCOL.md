# Frozen Experimental Protocol

## Research questions

**RQ1.** Under the same model, source-code context, role definitions, and total generated-token allowance, how do a single-agent workflow, a free-form multi-agent workflow, and a structured-evidence multi-agent workflow compare in distinguishing vulnerable functions from their fixed counterparts and localizing patch-relevant code?

**RQ2.** How are source-grounded vulnerability evidence elements preserved, omitted, changed, or newly introduced across ordinary agent handoffs, and which handoff outcomes are associated with incorrect final verdicts?

**RQ3.** When predefined vulnerability-analysis faults are inserted into an upstream handoff, how often do free-form and structured-evidence workflows repair, ignore, contain, propagate, or amplify them?

## Independent variable

`system` has three levels: `single`, `freeform_mas`, and `structured_mas`. The two MAS conditions use the same analyst, refuter, and adjudicator prompts. Only the downstream representation of upstream findings changes: prose versus typed JSON evidence records.

## Primary statistical unit

The vulnerability pair is the primary unit. Each pair contains one vulnerable function and its patched counterpart. Individual claims and agent messages are process observations, not independent samples for end-task significance tests.

## Dataset controls

- Development and test projects are disjoint.
- The same project contributes at most the configured number of pairs.
- CVE identifiers, CWE labels, commit messages, patch statements, and version labels are hidden from the model.
- Oversized functions are excluded before model execution; exclusions are documented by the preparation manifest and configuration.
- Prompt and schema changes are made using the development split only.

## Outcomes

### RQ1

- vulnerable-version recall;
- fixed-version false-positive rate;
- balanced accuracy with abstention treated as error;
- pair-correct rate;
- abstention and selective accuracy;
- any-claim and first-claim overlap with aligned vulnerable patch lines;
- parse-failure rate;
- total prompt/completion tokens and latency.

### RQ2

Automatic process measures:

- valid source-location rate;
- exact/normalized code-quote grounding rate;
- patch-overlap rate;
- grounded analyst claims retained in the final output;
- grounded claims omitted or explicitly rejected;
- line drift and polarity change among matched claims;
- unsupported final claims;
- explicit downstream refutation of unsupported upstream claims;
- harmful loss associated with an incorrect verdict.

Manual audit:

- semantic support of analyst and final claims;
- relevance of cited locations;
- transition classification: retained, corrected, omitted, distorted, or invented;
- independent agreement and adjudication.

### RQ3

Faults are introduced only into the analyst-to-refuter handoff and are assigned claim ID `F1`:

- `wrong_location` on vulnerable versions;
- `false_safe_guard` on vulnerable versions;
- `false_missing_guard` on fixed versions;
- `false_reachability` on fixed versions.

Outcome labels:

- `repaired`: baseline was correct, faulted verdict remains correct, and F1 is explicitly refuted;
- `ignored`: baseline and faulted verdicts are correct, without explicit refutation;
- `contained`: final verdict is uncertain;
- `propagated`: F1 is accepted or a previously correct verdict becomes wrong in the fault direction;
- `amplified`: propagation is accompanied by additional unsupported final claims;
- `indeterminate`: none of the predefined rules applies.

## Statistical plan

- Cluster bootstrap confidence intervals resample vulnerability pairs.
- Cochran's Q tests the global difference in pair-correctness among all three systems.
- Exact pairwise McNemar tests use Holm correction.
- Paired Wilcoxon tests compare token and latency distributions with Holm correction.
- Report effect estimates and intervals, not p-values alone.
- Treat RQ2 natural-handoff relationships as associations. Only RQ3 involves controlled interventions.

## Go/no-go criteria after the pilot

Proceed to the frozen full run only when:

1. at least 90% of outputs are parseable;
2. model prompts fit without silent truncation;
3. line citations can be checked automatically;
4. the manual annotation guide can be applied consistently to a small sample;
5. each injected fault is observable in the downstream logs;
6. no ground-truth metadata appears in model prompts.
