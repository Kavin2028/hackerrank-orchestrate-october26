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

The first command writes root-level `output.csv`. The second regenerates it, evaluates public samples, runs synthetic regression tests, validates output structure, selected evidence states and timestamps, and writes evaluation and usage reports under `code/evaluation/`. It also writes reproducible metrics and sample predictions under `tmp/`.

Build and independently verify the submission:

```text
python code/package.py
python code/evaluation/verify_package.py
```

The ZIP contains the required reports at `evaluation/evaluation_report.md` and `evaluation/usage_report.md`, as well as the development copies under `code/evaluation/`. The verifier extracts to a new temporary workspace, supplies the participant dataset separately, runs with a fresh OCR cache, and compares the output byte for byte. Windows OCR requires a local process allowed to access Windows Runtime APIs; a restrictive sandbox may prevent image reads. If `python` opens the Microsoft Store, use an installed Python executable or the `py` launcher instead.

Optional inputs:

```text
python code/main.py --dataset dataset --requests sample_deletion_requests.csv --output tmp/sample_predictions.csv
```

## Architecture

Current identities and identity-change history supply exact aliases with availability times. CSV activities add grounded catalog links. Evidence adapters read JSON exports, execute supplied SQL in an isolated in-memory SQLite database, correlate multi-line service logs by trace ID, extract PDF text, and OCR application screenshots. OCR caches use image-content hashes. Record observations carry their source IDs, observed times, manifest capture times, and copy scopes. Evidence after audit_at is excluded. Scoped inventory absence checks apply only to evidenced subject batches. Each physical copy has an independent timeline; a surviving older replica defeats newer primary absence.

Policy decisions are derived from `deletion_rules.csv`. The planner sorts findings, remediation, and verification according to the contract. It disables active flows and blocks restores before deleting/redacting/anonymizing records. Required retained records receive presence verification. Proposed actions and future verification use blank evidence IDs.

`main.py` never reads sample answers. The evaluator alone compares predictions against public `sample_output.csv`. There are no case-ID mappings, hardcoded answer rows, or filename-specific answer branches.

## Known limitations

Read `code/evaluation/evaluation_report.md` and `code/BLOCKERS.md` before submission. Expected-answer equivalence is not achieved. The implementation does not recover every resource link, particularly for absent and fully anonymized records, and will not guess IDs or copy canonical answers. Missing required retained records force INCOMPLETE rather than false presence verification, but the allowed operation vocabulary cannot express their recovery. Repeated-subject request scope, conditional policies, business documents without catalog mappings, and conflicting dependency/serialization rules still need resolution. The reports disclose measured public performance and do not claim hidden accuracy or full semantic completeness. The pipeline proposes actions and never modifies source systems. Interview notes are in `code/INTERVIEW_NOTES.md`.

The final-run usage report excludes the separate Codex development session and reports local OCR and deterministic inference honestly.
