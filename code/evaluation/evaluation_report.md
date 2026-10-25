# Evaluation report

## Reproduction

Run `python code/evaluation/main.py` from the repository root. This runs the full dataset, evaluates the 32 public samples, validates the submission contract, and runs six independent synthetic tests. Public expected outputs are read only here, never by the predictor. Hidden answer accuracy is unknown.

## Measured public-sample results

- Status accuracy: 29/32 (90.62%).
- Exact row accuracy (status and entire JSON sequence): 8/32 (25.00%).
- Sequence accuracy (entire ordered JSON array): 8/32 (25.00%).
- Step precision (including step numbers): 114/160 (71.25%).
- Step recall: 114/193 (59.07%).
- Positional field accuracy across seven fields, counting missing/extra fields as wrong: 952/1365 (69.74%).

## Full-run validation

- Requests: 518; generated rows: 518.
- Status counts: {'INCOMPLETE': 354, 'COMPLETE': 154, 'NOT_APPLICABLE': 10}.
- Structural/schema, operation/state, evidence-cutoff, and ordering errors: 0.
- Rows requiring manual evidence review: 1.
- End-to-end run time with existing OCR cache: 1.68 seconds.
- Synthetic regression suite exit code: 0.

## Independent evaluation cases

1. A data-access request explicitly prohibiting deletion yields NOT_APPLICABLE and no actions.
2. A successful deletion observation after audit_at cannot override an earlier present record.
3. A historical email resolves the subject while a required security record is preserved.
4. A replica containing a profile defeats an absent primary at the same snapshot time.
5. A tombstone may keep its stable reference but must remove direct identifiers and email hashes.
6. Restore blocking must precede record deletion; future actions have blank evidence IDs.

## Failures and improvements

Initial parsing missed syslog, pipe, cloud, and application log envelopes. The parser now normalizes each, correlates traces, and recognizes readback, PII scans, heartbeat, and restore checks. It distinguishes support attachments and secondary contact indexes from shared support messages. Screenshot parsing scopes identifiers to detail panels to reduce unrelated-customer matches. Multilingual deletion requests and explicit non-deletion requests are handled separately.

Exact step coverage remains incomplete. In particular, absent or fully anonymized records can have no recoverable subject link in evidence available before the cutoff. The implementation does not invent identifiers or copy canonical answers to fill these gaps. Some selected records may still be associated too broadly in complex business artifacts. Cases without any linked state evidence are conservatively INCOMPLETE with an empty step array, flagged for manual review; their missing resource plan means they do not fully satisfy the semantic output contract. Policy application is deterministic by category; complex retention conditions and cross-source conflicts need further semantic review. This is a runnable baseline, not a claim of hidden-test correctness or a fully verified deletion audit.

### Public sample mismatches

- case_01: status incorrect; predicted 0 steps, expected 1; exact-step matches 0.
- case_02: status incorrect; predicted 0 steps, expected 1; exact-step matches 0.
- case_03: status correct; predicted 2 steps, expected 3; exact-step matches 2.
- case_04: status incorrect; predicted 0 steps, expected 2; exact-step matches 0.
- case_06: status correct; predicted 3 steps, expected 4; exact-step matches 2.
- case_07: status correct; predicted 3 steps, expected 4; exact-step matches 2.
- case_08: status correct; predicted 3 steps, expected 4; exact-step matches 2.
- case_09: status correct; predicted 3 steps, expected 5; exact-step matches 2.
- case_10: status correct; predicted 3 steps, expected 4; exact-step matches 2.
- case_17: status correct; predicted 7 steps, expected 5; exact-step matches 3.
- case_18: status correct; predicted 12 steps, expected 14; exact-step matches 8.
- case_20: status correct; predicted 6 steps, expected 8; exact-step matches 4.
- case_21: status correct; predicted 1 steps, expected 3; exact-step matches 0.
- case_22: status correct; predicted 7 steps, expected 8; exact-step matches 4.
- case_23: status correct; predicted 6 steps, expected 8; exact-step matches 4.
- case_24: status correct; predicted 6 steps, expected 7; exact-step matches 6.
- case_25: status correct; predicted 1 steps, expected 3; exact-step matches 0.
- case_26: status correct; predicted 4 steps, expected 6; exact-step matches 0.
- case_27: status correct; predicted 4 steps, expected 6; exact-step matches 0.
- case_28: status correct; predicted 4 steps, expected 6; exact-step matches 0.
- case_29: status correct; predicted 12 steps, expected 14; exact-step matches 8.
- case_30: status correct; predicted 12 steps, expected 14; exact-step matches 8.
- case_31: status correct; predicted 2 steps, expected 3; exact-step matches 0.
- case_32: status correct; predicted 4 steps, expected 5; exact-step matches 2.

### Full-run evidence review

- case_61: no linked state evidence; conservative INCOMPLETE without an inventable resource plan
- No linked state evidence for case_61

### Validation errors

None.

### Synthetic test output

```text
test_future_observation_cannot_change_status (test_auditor.AuditTests.test_future_observation_cannot_change_status) ... ok
test_historical_email_and_retention (test_auditor.AuditTests.test_historical_email_and_retention) ... ok
test_non_deletion_never_authorizes_actions (test_auditor.AuditTests.test_non_deletion_never_authorizes_actions) ... ok
test_replica_presence_overrides_primary_absence (test_auditor.AuditTests.test_replica_presence_overrides_primary_absence) ... ok
test_restore_risk_precedes_record_removal (test_auditor.AuditTests.test_restore_risk_precedes_record_removal) ... ok
test_tombstone_keeps_stable_reference_only (test_auditor.AuditTests.test_tombstone_keeps_stable_reference_only) ... ok

----------------------------------------------------------------------
Ran 6 tests in 0.002s

OK

```
