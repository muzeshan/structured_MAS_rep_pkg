# Frozen Final Protocol

## Research questions

- **RQ1:** How does communication structure influence the effectiveness of agentic vulnerability analysis?
- **RQ2:** How does communication structure influence the integrity of vulnerability evidence across agent handoffs?
- **RQ3:** How does communication structure influence resilience to upstream evidence faults?

## Clean conditions

| Condition | Stage 1 | Stage 2 | Stage 3 |
|---|---|---|---|
| Self-refinement | analysis | self-critique | adjudication |
| Free-form MAS | prose analyst | prose refuter | adjudication |
| Structured MAS | typed analyst claim | typed refuter decision | adjudication |

Controls: same pinned Qwen2.5-Coder-3B model, deterministic decoding, code-only context, three calls, and output ceilings of 340/220/480 tokens.

## Dataset

Thirty SecVulEval development pairs were prepared. One pair (`secvuleval::15308::e753a7013efd`) was excluded because the target CWE-59 behavior was implemented in unseen helper functions and was not decidable from the supplied function. The clean experiment therefore contains 29 pairs and 58 versions per system.

## Corrected fault experiment

A deterministic 15-pair subset was selected before corrected fault outcomes were inspected. Each vulnerable and fixed version was tested under three mutations:

1. verdict inversion;
2. deletion of all upstream claims/evidence while retaining the verdict;
3. replacement by a standardized high-confidence false CWE-787 claim with an out-of-range span.

The identical canonical record was serialized to prose for self-refinement/free-form MAS and passed as JSON to Structured MAS. The upstream analyst was not rerun. Only critique/refutation and final adjudication were regenerated.

## Parsing

Final parse failure means the final report is absent. Upstream parse errors are tracked separately. In corrected RQ3, two structured refuter outputs required the frozen fallback and one structured final adjudication was invalid.
