# Repository Publishing Checklist

1. Create a public GitHub repository, for example `structured-handoffs-vulnerability-analysis`.
2. Replace `https://github.com/REPLACE-WITH-REPOSITORY` in `CITATION.cff`.
3. Review `DATA_AVAILABILITY.md` and confirm redistribution permissions for the source snippets embedded in the corrected RQ3 manifest.
4. Add the original clean stage-level JSONL file under `results/clean/raw/` when available.
5. Run:
   ```bash
   python scripts/analyze_results.py --verify
   PYTHONPATH=src pytest -q
   sha256sum -c SHA256SUMS.txt
   ```
6. Push a tagged release `v1.0.0`.
7. Connect the repository to Zenodo, archive the release, and add the DOI to `CITATION.cff`, the paper, and the repository README.
8. For double-blind review, use an anonymized archival repository or remove identifying metadata according to the venue policy.
