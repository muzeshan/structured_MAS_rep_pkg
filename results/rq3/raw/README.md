# Corrected RQ3 raw data

- `records-shard-000-of-001.jsonl`: 270 downstream fault-injection records.
- `rq3_corrected_fault_manifest.jsonl`: exact canonical clean handoffs, mutations, cases, and injection metadata.
- `rq3_selected_pairs.json`: deterministic 15-pair selection.

Observed format failures in the raw records:

- one invalid final structured adjudication under verdict inversion;
- two structured refuter parse errors handled by the frozen fallback, after which valid final reports were produced.

Accordingly, 269/270 records have valid final reports and three downstream stages contain parse errors. The paper's propagation counts are computed directly from the raw records, treating the invalid final report as an unsuccessful recovery.
