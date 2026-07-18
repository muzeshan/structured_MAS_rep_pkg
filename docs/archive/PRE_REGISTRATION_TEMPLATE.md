# Pre-registration and Protocol Freeze Template

Complete this document before opening frozen-test outputs. Commit it with a timestamped hash.

## 1. Study identity

- Working title:
- Authors:
- Registration/freeze date and time:
- Repository commit or artifact SHA-256:
- Frozen configuration directory:
- Planned venue:

## 2. Research questions

### RQ1 — End-to-end effectiveness

Under matched model, tool, code-context, call-count, and output-token ceilings, how do a single-agent self-refinement workflow, a free-form multi-agent workflow, and a structured-evidence multi-agent workflow compare in vulnerable/fixed pair correctness and localization?

### RQ2 — Evidence preservation

How are vulnerability-relevant evidence elements preserved, omitted, distorted, or invented across agent handoffs, and which handoff failures are associated with incorrect final decisions?

### RQ3 — Fault recovery

When controlled vulnerability-analysis faults are inserted into an upstream handoff, how often do free-form and structured-evidence workflows propagate, correct, amplify, or contain them?

Record any wording changes before the final run:

## 3. Hypotheses

State directional hypotheses or explicitly state that analyses are exploratory.

- H1:
- H2:
- H3:
- Exploratory analyses:

## 4. Dataset

- Dataset name and immutable revision:
- Preparation configuration hash:
- Number of raw vulnerable rows:
- Number of valid pairs after pairing:
- Exclusion rules:
- Exact deduplication rule:
- Project/campaign grouping rule:
- Development pairs:
- Frozen test pairs:
- Annotation pairs:
- Fault pairs:
- Cross-model subset:
- Stability subset:
- Project overlap check result:
- Manual pairing-audit sample size and result:

## 5. Systems

### S0 — Single-agent self-refinement

- Model:
- Number of calls:
- Stage roles:
- Tool access:

### S1 — Free-form MAS

- Model:
- Number of calls:
- Roles:
- Handoff format:
- Tool access:

### S2 — Structured-evidence MAS

- Model:
- Number of calls:
- Roles:
- Evidence schema version/hash:
- Tool access:

Document all differences other than communication mode. Explain why each remaining difference is necessary.

## 6. Frozen model and inference configuration

- Model ID:
- Immutable model revision:
- Quantization:
- Inference backend:
- Hardware:
- Maximum input tokens:
- Maximum new tokens per stage:
- Batch size:
- Temperature:
- Top-p:
- Sampling:
- Base seed:
- Timeout/retry policy:
- Prompt protocol hash:

## 7. Primary outcomes

### RQ1 primary

- Pair-correct rate.
- Definition: vulnerable version predicted vulnerable AND fixed counterpart predicted not vulnerable.
- Abstentions and parse failures count as incorrect for the primary estimate.

### RQ1 secondary

- Vulnerable-version precision, recall, and F1.
- Fixed-version false-positive rate.
- Coverage/selective accuracy.
- Patch-line localization hit and F1 as proxies.
- CWE overlap as a secondary taxonomy measure.
- Tokens and latency.

### RQ2 primary

- Manually adjudicated evidence support, retention, distortion, repair, and final grounding.
- Rating fields and allowed categories:
- Number of annotators:
- Adjudication procedure:

### RQ2 secondary

- Automatic patch/CWE-proxy retention and unsupported-finding measures.
- Explicit statement that these are not semantic ground truth.

### RQ3 primary

- Fault propagation rate by fault family and handoff mode.

### RQ3 secondary

- Repair, containment, amplification proxy, verdict-repaired/evidence-unresolved rate, parse failure, tokens, and latency.

## 8. Statistical analysis

- Bootstrap iterations:
- Confidence interval type:
- Cochran's Q scope:
- McNemar pairwise comparisons:
- Multiple-testing correction:
- Paired cost/latency test:
- Statistical unit:
- Missing-output policy:
- Repeated-run/stability policy:
- Planned effect sizes:
- Significance threshold, if used:

## 9. RQ3 fault definitions

### Label flip

- Eligible cases:
- Fault construction:
- Propagated:
- Repaired:
- Contained:

### Wrong CWE

- Eligible cases:
- Wrong-CWE selection rule:
- Propagated:
- Repaired:
- Evidence unresolved:

### Wrong location

- Eligible cases:
- Wrong-line selection rule:
- Propagated:
- Repaired:
- Evidence unresolved:

Any fault excluded from the primary analysis and why:

## 10. Manual annotation

- Annotator qualifications:
- Training examples:
- Pilot annotation size:
- Packet blinding:
- Whether annotators know the dataset or paper hypothesis:
- Resolution of system-format visibility:
- Agreement measures:
- Adjudicator:
- Exclusion policy:

## 11. Stop/go criteria

Before the final run, require:

- [ ] At least 90% of pilot final outputs parse under the frozen schema.
- [ ] No hidden label/CVE/commit leakage in prompts.
- [ ] Project-disjoint split verified.
- [ ] Prompt lengths fit without truncation.
- [ ] Controlled faults are generated exactly as specified.
- [ ] Annotation fields can be applied consistently in a pilot.
- [ ] Compute and storage are sufficient.

## 12. Deviations

After freezing, log every deviation here before analysis. Do not silently alter prompts, data, exclusions, metrics, or tests.

| Date | Deviation | Reason | Affected outputs | Decision |
|---|---|---|---|---|
