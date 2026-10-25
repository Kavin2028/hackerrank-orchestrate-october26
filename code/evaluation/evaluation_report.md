# Evaluation report

Final run started UTC: 2026-10-25T12:56:29.195063+00:00. Output SHA-256: b0906fe5c2fd980b91d9d2a1181bd2ffc294fd2d32f4a31a2098920fac5fbfec.

## Reproduction

Run `python code/evaluation/main.py` from the repository root. This runs the full dataset, evaluates the 32 public samples, validates the submission contract, and runs the independent synthetic regression suite. Public expected outputs are read only here, never by the predictor. Hidden answer accuracy is unknown. Passing structure validation does not prove complete evidence discovery.

## Measured public-sample results

- Status accuracy: 29/32 (90.62%).
- Exact row accuracy (status and entire JSON sequence): 8/32 (25.00%).
- Sequence accuracy (entire ordered JSON array): 8/32 (25.00%).
- Step precision (including step numbers): 112/163 (68.71%).
- Step recall: 112/193 (58.03%).
- Positional field accuracy across seven fields, counting missing/extra fields as wrong: 948/1379 (68.75%).

## Full-run validation

- Requests: 518; generated rows: 518.
- Status counts: {'INCOMPLETE': 352, 'COMPLETE': 156, 'NOT_APPLICABLE': 10}.
- Structural/schema, operation/state, evidence-cutoff, and ordering errors: 0.
- Rows requiring manual evidence review: 0.
- End-to-end run time with existing OCR cache: 18.30 seconds.
- Synthetic regression suite exit code: 0.

## Independent evaluation cases

1. A data-access request explicitly prohibiting deletion yields NOT_APPLICABLE and no actions.
2. A successful deletion observation after audit_at cannot override an earlier present record.
3. A historical email resolves the subject while a required security record is preserved.
4. A replica containing a profile defeats an absent primary at the same snapshot time.
5. A tombstone may keep its stable reference but must remove direct identifiers and email hashes.
6. Restore blocking must precede record deletion; future actions have blank evidence IDs.
7. An older surviving replica remains a violation after a newer primary absence; its own later removal resolves it.
8. An absent required retained record cannot yield COMPLETE or a false evidence-backed presence check.
9. A successful deletion claim alone cannot prove absence.
10. Unavailable identity history, future captures, and future catalog links cannot establish an earlier state.
11. An unrelated inventory batch cannot clear records from another subject batch.
12. Nested identifier lists and multilingual negation are handled explicitly; absent analytics do not expose identifiers.

## Failures and improvements

Initial parsing missed syslog, pipe, cloud, and application log envelopes. The parser now normalizes each, correlates traces, and recognizes readback, PII scans, heartbeat, and restore checks. It distinguishes support attachments and secondary contact indexes from shared support messages. Screenshot parsing scopes identifiers to detail panels to reduce unrelated-customer matches. Multilingual deletion requests and explicit non-deletion requests are handled separately.

The two documented false-COMPLETE defects have regression coverage and are fixed: each physical copy has its own timeline, and missing required retained records force INCOMPLETE. Identity aliases are filtered by availability; snapshot absence is scoped to evidenced subject batches; parent-resource links are preserved. The catalog and screenshot now establish the attachment for case_61. OCR caches include content hashes. Both exact archive-root evaluation report paths are packaged.

Expected-answer equivalence remains unachieved. Absent or fully anonymized records sometimes have no recovered subject link before audit_at. The implementation does not infer IDs from case numbers, correlate unrelated operations by timing, invent missing evidence, or copy canonical answers. Older still-evidenced records for the same subject can add steps omitted by public expected plans. Missing mandatory retained/shared records require recovery, which the permitted operation vocabulary cannot express; these cases receive diagnostics and future checks rather than false verification. Retention expiry alone does not authorize deletion without an applicable rule. Some business documents lack grounded system/resource catalog mappings. See code/BLOCKERS.md for concrete gaps. No hidden accuracy or full semantic completeness is claimed.

### Public sample mismatches

- case_01: status incorrect; predicted 0 steps, expected 1; exact-step matches 0.
- case_02: status incorrect; predicted 0 steps, expected 1; exact-step matches 0.
- case_03: status correct; predicted 2 steps, expected 3; exact-step matches 2.
- case_04: status incorrect; predicted 0 steps, expected 2; exact-step matches 0.
- case_06: status correct; predicted 3 steps, expected 4; exact-step matches 2.
- case_07: status correct; predicted 6 steps, expected 4; exact-step matches 0.
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

None.

### Validation errors

None.

### Synthetic test output

```text
test_absent_analytics_does_not_report_exposed_pii (test_auditor.AuditTests.test_absent_analytics_does_not_report_exposed_pii) ... ok
test_catalog_reference_requires_whole_token (test_auditor.AuditTests.test_catalog_reference_requires_whole_token) ... ok
test_document_mapping_waits_for_catalog_availability (test_auditor.AuditTests.test_document_mapping_waits_for_catalog_availability) ... ok
test_future_capture_excluded_even_with_earlier_event (test_auditor.AuditTests.test_future_capture_excluded_even_with_earlier_event) ... ok
test_future_observation_cannot_change_status (test_auditor.AuditTests.test_future_observation_cannot_change_status) ... ok
test_historical_email_and_retention (test_auditor.AuditTests.test_historical_email_and_retention) ... ok
test_later_catalog_link_is_not_available_earlier (test_auditor.AuditTests.test_later_catalog_link_is_not_available_earlier) ... ok
test_missing_retained_record_never_proves_presence (test_auditor.AuditTests.test_missing_retained_record_never_proves_presence) ... ok
test_multilingual_non_deletion (test_auditor.AuditTests.test_multilingual_non_deletion) ... ok
test_nested_list_identifiers_are_not_anonymous (test_auditor.AuditTests.test_nested_list_identifiers_are_not_anonymous) ... ok
test_non_deletion_never_authorizes_actions (test_auditor.AuditTests.test_non_deletion_never_authorizes_actions) ... ok
test_older_replica_survives_new_primary_absence (test_auditor.AuditTests.test_older_replica_survives_new_primary_absence) ... ok
test_replica_own_newer_absence_resolves_its_presence (test_auditor.AuditTests.test_replica_own_newer_absence_resolves_its_presence) ... ok
test_replica_presence_overrides_primary_absence (test_auditor.AuditTests.test_replica_presence_overrides_primary_absence) ... ok
test_restore_risk_precedes_record_removal (test_auditor.AuditTests.test_restore_risk_precedes_record_removal) ... ok
test_tombstone_keeps_stable_reference_only (test_auditor.AuditTests.test_tombstone_keeps_stable_reference_only) ... ok
test_unavailable_historical_alias_does_not_link_subject (test_auditor.AuditTests.test_unavailable_historical_alias_does_not_link_subject) ... ok
test_unrelated_inventory_batch_cannot_clear_record (test_auditor.AuditTests.test_unrelated_inventory_batch_cannot_clear_record) ... ok
test_unverified_delete_claim_does_not_prove_absence (test_auditor.AuditTests.test_unverified_delete_claim_does_not_prove_absence) ... ok

----------------------------------------------------------------------
Ran 19 tests in 1.944s

OK

```
