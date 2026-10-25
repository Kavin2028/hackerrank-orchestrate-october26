# Ghost Data Still Exists

A local deletion-audit pipeline that combines machine-learning OCR with deterministic identity matching, temporal evidence reconstruction, policy application, and ordered remediation planning.

## Setup and execution

Use Python 3.10 or newer. Install `python -m pip install -r code/requirements.txt` from the repository root. Keep the participant dataset in `dataset/` next to `code/`.

On Windows, OCR uses the built-in Windows.Media.Ocr API through Windows PowerShell. Run from a normal local terminal that can access Windows Runtime APIs. On Linux/macOS, install Tesseract with English language data and ensure `tesseract` is on PATH. OCR text is cached in `tmp/ocr/`; deleting this directory forces re-extraction. No API key is required. All evidence formats are read from the supplied manifest.

Run:

```text
python code/main.py
python code/evaluation/main.py
```

The first command writes root-level `output.csv`. The second regenerates it, evaluates public samples, runs synthetic regression tests, validates output structure and evidence timestamps, and writes the required evaluation and usage Markdown reports under `code/evaluation/`.

Optional inputs:

```text
python code/main.py --dataset dataset --requests sample_deletion_requests.csv --output tmp/sample_predictions.csv
```

## Architecture

Current identities and identity-change history supply exact aliases. CSV activities add grounded catalog links. Evidence adapters read JSON exports, execute supplied SQL in an isolated in-memory SQLite database, correlate multi-line service logs by trace ID, extract PDF text, and OCR application screenshots. Record observations carry their source IDs, observed times, and manifest capture times. Evidence after audit_at is excluded. Complete SQL and JSON snapshots provide scoped absence checks; replica presence overrides simultaneous primary absence.

Policy decisions are derived from `deletion_rules.csv`. The planner sorts findings, remediation, and verification according to the contract. It disables active flows and blocks restores before deleting/redacting/anonymizing records. Required retained records receive presence verification. Proposed actions and future verification use blank evidence IDs.

`main.py` never reads sample answers. The evaluator alone compares predictions against public `sample_output.csv`. There are no case-ID mappings, hardcoded answer rows, or filename-specific answer branches.

## Known limitations

Read `evaluation/evaluation_report.md` before submission. This baseline does not recover every resource link, particularly for absent and fully anonymized records. A case without any linked state evidence is conservatively INCOMPLETE with an empty step array and is flagged for review. Its missing resource plan does not fully satisfy the semantic output contract. Complex PDF/image relationships, retention conditions, dependency ordering, and cross-source contradictions need further review. The reports disclose measured sample performance and do not claim hidden-test accuracy. The pipeline proposes actions and never modifies source systems.

The final-run usage report excludes the separate Codex development session and reports local OCR and deterministic inference honestly.
