# RQ2 Human Annotation Guide

## Purpose

The annotation evaluates whether agent handoffs preserve evidence that is actually supportable from the visible function. It does **not** ask annotators to reproduce the dataset's CVE label from memory.

Annotators receive:

- a blind item identifier;
- a blind system identifier;
- language;
- numbered code;
- analyst handoff;
- refuter/self-critique handoff;
- final structured report.

Annotators do not receive:

- project or package name;
- file path or function name;
- vulnerable/fixed status;
- CVE or CWE gold labels;
- fixing commit or patch;
- model identity;
- system's true workflow name.

The prose-versus-JSON communication form is inherently visible. Do not infer the study hypothesis from that form; judge the evidence only.

## General principles

1. Treat the visible code as the only authoritative technical source.
2. A dangerous API is not automatically exploitable.
3. Consider attacker control, reachability, preconditions, guards, and consequences.
4. A claim may be supportable even when the final binary verdict is uncertain.
5. A claim that depends on unavailable repository context may be marked `uncertain`, not automatically `no`.
6. Check every cited line. Nonexistent or unrelated citations are unsupported.
7. Do not use external knowledge of a project or CVE.

## Allowed categories

Use lowercase values exactly as shown.

### Binary-like fields

- `yes`
- `no`
- `partial`
- `uncertain`

Some fields also permit:

- `not_applicable`
- `no_upstream_error`

Do not leave a field blank unless instructed by the coordinator.

## Field definitions

### 1. `analyst_claim_supported`

Does the analyst's principal vulnerability claim follow from the visible code?

- `yes`: cited behavior and required logic are supportable.
- `partial`: some elements are correct, but a material precondition/path/guard claim is unsupported.
- `no`: central claim conflicts with or is absent from the code.
- `uncertain`: function context is insufficient to judge.

### 2. `analyst_evidence_complete`

Does the analyst provide enough evidence for its stated level of confidence?

Relevant elements vary by weakness but may include:

- source or attacker entry point;
- security-sensitive operation;
- path or reachability;
- trigger/precondition;
- guard or missing guard;
- consequence;
- exact line citation.

- `yes`: all material elements needed for the claim are present.
- `partial`: some material evidence is missing.
- `no`: evidence is largely absent or generic.
- `uncertain`: context prevents a fair completeness judgment.

### 3. `evidence_retained_to_refuter`

Does the second handoff preserve the analyst's supportable evidence accurately?

- `yes`: all material supportable elements remain available.
- `partial`: some material evidence is omitted but the core is retained.
- `no`: core supportable evidence is lost or replaced.
- `not_applicable`: analyst supplied no supportable evidence.
- `uncertain`: transition cannot be judged.

### 4. `evidence_distorted`

Does the second handoff materially alter an upstream claim without code support?

Examples:

- changing “possibly reachable” to “definitely reachable”;
- claiming a guard exists when none is visible;
- changing cited location or CWE without justification;
- turning an uncertain precondition into a fact.

- `yes`: at least one material distortion occurs.
- `no`: no material distortion is observed.
- `uncertain`: cannot judge from available context.

Omission alone is not distortion; record omission through the retention field.

### 5. `downstream_repaired_error`

Did the second handoff correctly identify and repair a material upstream error?

- `yes`: a wrong location, path, guard, precondition, or interpretation is explicitly corrected.
- `no`: a material upstream error exists but is not corrected or is amplified.
- `no_upstream_error`: no material upstream error required repair.
- `uncertain`: cannot determine whether the upstream claim was wrong.

### 6. `final_evidence_supported`

Are the final report's cited findings supported by the visible code?

- `yes`: all material final findings are supportable.
- `partial`: at least one is supportable, but another material element is unsupported.
- `no`: final evidence is absent, invented, or materially contradicted.
- `uncertain`: context is insufficient.

### 7. `final_verdict_supported_by_code`

Is the final `vulnerable`, `not_vulnerable`, or `uncertain` decision reasonable given only the visible function?

- `yes`: verdict is justified at its stated confidence.
- `partial`: direction may be plausible, but certainty is excessive or evidence incomplete.
- `no`: verdict contradicts the visible evidence.
- `uncertain`: the function cannot support a reliable decision.

This field is not the dataset's gold-label correctness. A dataset-labeled vulnerable function may still warrant an `uncertain` judgment when crucial repository context is missing.

## Annotation procedure

1. Read the code first without reading the handoffs.
2. Note likely security-sensitive operations and guards privately.
3. Read the analyst handoff and rate fields 1–2.
4. Read the refuter/self-critique handoff and rate fields 3–5.
5. Read the final report and rate fields 6–7.
6. Add concise notes for every `no`, `partial`, or `uncertain` rating.
7. Do not consult the private key or external sources.

## Training and pilot

Before full annotation:

- jointly discuss 8–10 non-test training examples;
- independently annotate 10 pilot items;
- resolve differences in category interpretation, not item outcomes;
- freeze this guide;
- independently annotate the final packet.

## Agreement and adjudication

- Compute raw agreement and Cohen's kappa before adjudication.
- The adjudicator sees both ratings and notes, then rechecks the code.
- Do not force agreement by changing one annotator's original file.
- Preserve original, merged, disagreement, and adjudicated files.
- Report agreement field by field; one aggregate kappa can hide important disagreement.
