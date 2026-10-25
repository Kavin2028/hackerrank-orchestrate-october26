# Solution completion checklist

Sources: `problem_statement.md` and the root `AGENTS.md`, read in full. Work through numbered items in order. Leave an item unchecked until its acceptance conditions are verified; existing files and past test passes alone do not establish completion. The user subsequently authorized working through all stages. Checked items are verified work, not a claim of complete expected-answer equivalence.

Current verified run: 518 rows; public status accuracy 29/32 (90.62%) and exact rows 8/32 (25%). Nineteen regressions pass. Both previously documented false-COMPLETE bugs are fixed; case_61 now has an evidence-backed attachment plan. A clean extraction using fresh OCR on all 11 images reproduces the output byte for byte. No challenge deadline is configured.

Expected-answer equivalence is NOT achieved. Unchecked requirements remain open. See code/BLOCKERS.md for concrete unlinked resources, repeated-subject scope differences, missing recovery operations, and dependency-order ambiguity. The final output SHA-256 is b0906fe5c2fd980b91d9d2a1181bd2ffc294fd2d32f4a31a2098920fac5fbfec. Baseline evidence is retained in tmp/baseline_evaluation_report.md and tmp/baseline_sample.csv.

## 1. Establish the baseline and enforce data boundaries

- [x] Record repository state and preserve existing uncommitted work.
- [x] Review applicable nested AGENTS.md files before editing their directories.
- [x] Run and save a reproducible baseline: public sample predictions, full output validation, and existing regression results.
- [x] Confirm prediction code reads participant-facing data under dataset/ only. Sample answers may be used by the evaluator only; exclude organizer truth, generator internals, hardcoded labels, and case-family shortcuts.
- [x] Keep root log.txt append-only; record every turn with authoritative harness/model metadata, UTF-8 and LF line endings. Redact secrets and real personal data.

Acceptance: baseline failures are recorded and the predictor/evaluator data boundary is verified.

## 2. Correct deletion authorization and identity resolution

- [x] Interpret multilingual request_text to distinguish deletion from access, correction, export, marketing opt-out, and explicit instructions against deletion.
- [x] Return NOT_APPLICABLE with [] for requests that do not authorize deletion.
- [x] Resolve request email through current and historical identity records; recover grounded names, emails, phones, hashes, and stable user references without merging unrelated subjects.
- [x] Respect audit_at for identity information as well as other evidence; later changes cannot alter an earlier decision.

Acceptance: independent cases cover deletion, non-deletion, historical email, multilingual wording, and unrelated-identity decoys.

## 3. Complete evidence ingestion and grounded retrieval

- [x] Read the manifest and inspect actual PDF, image, log, JSON, text, and SQL contents rather than inferring membership from filenames or manifest rows.
- [ ] Validate extraction of business-artifact relationships and OCR facts; associate evidence through grounded identifiers, resource links, systems, and timestamps.
- [x] Cover primary, regional, reporting, and failover SQL copies, attachments, exports, indexes, analytics, archives, and backups where supplied evidence links them.
- [x] Distinguish proven scoped absence/anonymization from failure to retrieve a record; prevent unrelated global activity from becoming case evidence.
- [x] Investigate case_61 from participant-visible sources and produce a supported resource plan; do not invent a resource or mark an empty plan complete.

Acceptance: relevant resources have traceable provenance; missing evidence is explicitly investigated, and evidence formats are checked structurally or visually as appropriate.

## 4. Fix temporal reconstruction and replica handling

- [x] Exclude evidence unavailable by audit_at, accounting for capture and observation/event times.
- [x] Treat workflow statuses and operation results as claims; establish resulting state from supplied evidence.
- [x] Reconstruct physical copies independently before aggregating resource state.
- [x] Fix the documented bug: an older extant replica must not disappear merely because a newer primary observation reports ABSENT.
- [ ] Resolve cross-source contradictions using grounded scope and time rather than choosing a convenient latest event.
- [x] Add regression coverage for independent copy timelines, later evidence, simultaneous conflicting snapshots, and unverified successful operations.

Acceptance: no surviving evidenced copy is discarded by an observation about a different copy.

## 5. Apply every policy condition and preserve required records

- [ ] Apply deletion_rules.csv by category and applicable condition, including retention conditions, rather than category alone.
- [ ] Correctly select DELETE, REDACT, ANONYMIZE, or RETAIN treatment for every relevant record.
- [x] Preserve account tombstones' stable reference while removing prohibited name, email, phone, email hash, and other direct identifiers.
- [x] Fix the documented bug: a mandatory retained record observed ABSENT cannot produce COMPLETE or a false evidence-backed VERIFY_RECORD_PRESENT.
- [ ] Determine how missing required retained records can be represented within the allowed operations; do not invent restoration operations or fabricate evidence. Document any genuine specification gap and seek clarification only if it prevents a valid answer.
- [ ] Verify anonymization actually removes the subject link, and verify required retained records remain available.

Acceptance: independent tests cover missing retained records, conditional retention, tombstones, redaction, and irreversible unlinking.

## 6. Build complete findings, remediation, and verification plans

- [ ] Report every supported remaining record, exposed identifier, active data flow, and restore risk.
- [ ] Disable relevant copying/recreation processes and block unsafe restores before dependent record changes; cover downstream copies before sources when dependency requires it.
- [x] Supply a verification check for every remediated record/process and required final retained state.
- [ ] COMPLETE contains only evidence-backed verification; INCOMPLETE contains complete findings, remediation, and future checks; NOT_APPLICABLE contains [].
- [x] Use only the permitted phases, operations, and corresponding states.
- [ ] Follow the problem statement's exact serialization order: phase, operation order in its table, system_id ascending, resource_id ascending. Verify dependency constraints against this required order; investigate any concrete conflict rather than silently violating either rule.
- [x] Findings and COMPLETE verification cite the proving file_id/activity_id/audit_id at or before audit_at. INCOMPLETE remediation and future verification have empty evidence_id.

Acceptance: no unsupported claims, missing required treatment, unauthorized actions, invented operations, or unexplained empty authorized-case plans remain.

## 7. Enforce the complete CSV and JSON contract

- [x] Write root output.csv with exactly case_id,deletion_status,steps_json in that order.
- [x] Include exactly the 518 requested case IDs once each, sorted by case_id.
- [x] Restrict deletion_status to COMPLETE, INCOMPLETE, NOT_APPLICABLE.
- [x] Parse every steps_json as an array; require exactly step_no, phase, system_id, resource_id, operation, state, evidence_id on every step.
- [x] Number steps consecutively from 1 and validate phase/operation/state, ordering, citation existence, temporal eligibility, and citation relevance.
- [ ] Validate semantic completion as well as schema: no missing mandatory retained records, surviving prohibited copies, or active recreation paths can pass as COMPLETE.
- [x] Confirm deterministic results for unchanged inputs.

Acceptance: all structural checks pass and all diagnosed semantic failures are resolved or explicitly identified as unresolved blockers.

## 8. Evaluate and document measured results honestly

- [x] Evaluate all 32 public samples without letting canonical answers enter prediction logic.
- [x] Report status, step-level, field-level, and sequence accuracy with explicit definitions and denominators.
- [x] Include at least three participant-created evaluation cases; retain and extend meaningful regressions for the known defects.
- [x] Investigate sample mismatches and record failures found, improvements made, and remaining limitations. Do not substitute hardcoded expected answers for general fixes.
- [x] Put final measured results directly into evaluation/evaluation_report.md within the submitted archive; verify its archive path rather than assuming code/evaluation/ is equivalent.
- [x] State that hidden-answer accuracy is unavailable. The specification supplies no numerical passing threshold; do not invent one or equate valid CSV with correctness.

Acceptance: reports reproduce from the final code, tests pass, and unresolved mismatches are accurately disclosed.

## 9. Produce the final run and usage accounting

- [x] Run the final solution end to end over all 518 requests using the supported terminal command.
- [x] Ensure the recorded final run is the one that produced the submitted output.csv.
- [x] Record model providers/names, calls, input/output tokens, total and average tokens per request, estimated total/per-request cost, and per-model plus overall totals where applicable.
- [x] Distinguish local OCR/deterministic inference from paid generative calls; report unavailable model identifiers or unmeasured costs honestly and separate development usage from final-run inference.
- [x] Write this accounting directly into evaluation/usage_report.md within code.zip, tied to the final run.

Acceptance: final output, runtime details, evaluation results, and usage reports describe the same implementation and run.

## 10. Verify documentation and build a clean submission package

- [x] Provide README.md with exact dependency installation, OCR prerequisites, setup, and terminal run/evaluation commands; resolve dataset/output paths relative to the repository root.
- [x] Package runnable source, prompts/configuration if used, README.md, and evaluation/evaluation_report.md plus evaluation/usage_report.md.
- [x] Verify archive-root layout and documented commands work together; fix the current packaging layout if it does not meet those exact report paths.
- [x] Exclude dataset/, virtual environments, dependency caches, nested archives, credentials, sensitive configuration, and real personal data from code.zip.
- [x] Read credentials from environment variables only; exclude any local .env file.
- [x] Extract code.zip into a clean location, supply participant dataset separately, install documented dependencies, and run without relying on existing OCR caches.
- [x] Verify archive integrity, all 518 output rows, and reproducible output; regenerate the package after any source/report change.

Acceptance: a clean extracted submission reproduces the validated final output using the README alone.

## 11. Assemble final deliverables and interview preparation

- [x] Deliver code.zip, root output.csv, and root log.txt as chat_transcript.
- [x] Prepare an accurate AI interview explanation of identity resolution, multimodal evidence retrieval, temporal/copy reconstruction, policy decisions, ordered remediation, evaluation, limitations, and cost.
- [x] Review remaining blockers before calling the solution complete; list any unresolved correctness limitations explicitly.
- [ ] Submit only when requested by the user, using the exact official challenge URL below.

Official challenge/submission URL: https://www.hackerrank.com/contests/hackerrank-orchestrate-october26/challenges/ghost-data-still-exists

Dataset-maintenance rules are conditional: do not modify/regenerate participant data for solution improvements. If separately authorized dataset maintenance changes generator logic or the contract, follow AGENTS.md §7, including both generator validators and representative artifact review; never use private truth for predictions.
