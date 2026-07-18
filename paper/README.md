# MAS-GAIN 2026 Overleaf project

**Paper:** Structured Evidence Handoffs in LLM Multi-Agent Vulnerability Analysis: Accuracy, Traceability, and Fault Propagation

## Compile in Overleaf

1. Choose **New Project -> Upload Project**.
2. Upload the ZIP.
3. Set `main.tex` as the main document.
4. Use pdfLaTeX and BibTeX (Overleaf handles this automatically).

## Formatting note

The current official MAS-GAIN 2026 workshop page specifies the ACM Primary Article Template with:

```latex
\documentclass[sigconf]{acmart}
```

and an 8-page regular-paper limit including references. The EasyChair CFP still displays older IEEE wording. The project follows the current official workshop page. Confirm the required template in EasyChair or with the organizers immediately before submission.

Official page: https://masgain.github.io/masgain/masgain2026/

## Author metadata

The current project contains Muhammad Umar Zeshan's author block. Add all coauthors and verify affiliations before submission. To create an anonymous version, change the first line to:

```latex
\documentclass[sigconf,anonymous,review]{acmart}
```

and remove identifying artifact text if required. The workshop page currently does not state an anonymity policy.

## Result provenance

The paper is based on:

- 29 eligible SecVulEval vulnerable-fixed pairs;
- 58 code versions and 174 clean workflow records;
- three workflows: self-refinement, free-form MAS, and structured MAS;
- Qwen2.5-Coder-3B-Instruct, pinned revision `488639f1ff808d1d3d0ba301aef8c11461451ec5`;
- deterministic decoding and matched stage ceilings `340/220/480`;
- a corrected RQ3 experiment with 270 records over 15 pairs, 3 systems, and 3 fault types.

The `data/` directory contains the aggregate CSV files used to write the tables. The paper deliberately describes the study as exploratory because the protocol was tuned on the development sample.

## Important checks before submission

- Add all coauthors and final affiliations.
- Add an artifact/replication URL if available.
- Confirm the ACM-versus-IEEE template with the organizers.
- Recompile and confirm the PDF does not exceed 8 pages including references. The validated preview in this package is 6 pages.
- Do not weaken the stated limitations: the clean run reused development pairs, RQ2 is automatic lineage analysis rather than human semantic annotation, and RQ3 lacks a no-fault canonicalized control.
