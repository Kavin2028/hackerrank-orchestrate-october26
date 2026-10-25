# Expected-answer equivalence is not established

This document records concrete participant-data gaps and specification ambiguities. It is an evaluation document, never read by the prediction pipeline. Public expected answers may identify a mismatch; they cannot supply a missing prediction-time identity link.

## Unlinked absent and anonymized resources

The public answer for case_01 requires account_001 and evidence_54. That SQL snapshot contains only three unrelated profiles in its primary table and those profiles plus account_005 in the failover table. Neither account_001 nor the subject's identifiers occurs in it. The only activity for account_001 names the resource and reports a deletion result, without a subject identifier. The predictor cannot derive that subject-to-resource mapping from the snapshot or that operation. The same issue affects case_02's account_002 and case_04's account_004.

For case_03, analytics_9406 is read in evidence_94 with lookup_key, customer_reference, email, phone, and email_hash all null. Its activity row reports anonymization but has no subject. The content establishes anonymous state of that resource, but does not establish which person it formerly represented. Inferring a person from the resource number, the operation's proximity to another operation, or the sample answer would violate grounded matching.

For case_04, analytics_901 in evidence_56 has all identity fields null; its activity again provides no subject. For several later samples, profile lookups have a resource ID and a null profile but no lookup identity. Similar ambiguities affect fully anonymized analytics rows. The current implementation cannot recover those links, and public accuracy remains incomplete. This is not a proof that every mismatch is impossible: other retrieval improvements may still help.

## Different requests for the same subject

The catalog explicitly links object_19 to the subject of case_61, and evidence_46 shows its stored attachment. The same person also appears in public case_07 at a later cutoff. No supplied eligible removal observation for that object has been established, so the implementation retains it as a finding in the later audit even though its public expected plan omits it. Similarly, the catalog and reference screen establish tombstone_17 for a subject who appears in a later public sample whose expected plan omits that reference. The scope of earlier requests versus still-existing copies needs clarification; removing these records purely to match a case-specific expected row would be a shortcut.

## Missing mandatory retained records

The contract requires mandatory retained records to remain available, but provides no finding or remediation operation for an already missing required retained record. REPORT_REMAINING_RECORD means an unwanted record exists, and REPORT_EXPOSED_PII means identifiers remain exposed; neither describes missing required data. No RESTORE_RECORD operation is allowed. The fixed predictor returns INCOMPLETE with a future presence check and a diagnostic rather than fabricating presence, inventing an operation, or claiming a complete recovery plan.

## Ordering and policy limits

The problem statement prescribes phase, operation, system, and resource sorting. AGENTS.md additionally requires downstream-before-source remediation where a dependency requires it. Alphabetical system sorting can place account_service before search_service for two DELETE_RECORD steps. The implementation follows the explicit serialization order and stops data flows/restores first, but the format has no field for a separate execution dependency graph. A concrete conflicting case needs an authoritative interpretation rather than an invented sequence.

The rules state conditions for security retention, legal holds, shared support messages, and subject-owned attachments. Where evidence supplies no applicable retention boundary, hold status, ownership, or catalog mapping, complete conditional-policy verification remains uncertain. Expired retention alone is not treated as authorization to delete records without a supplied rule requiring that treatment.

## What is needed to close these gaps

Participant-visible, timestamped subject-to-resource links for absent/anonymized resources; explicit snapshot subject/copy scope where ambiguous; clarification of repeated-subject request scope, recovery vocabulary, and conflicting ordering requirements. These must be official participant-facing evidence or contract clarifications. Organizer truth, hardcoded sample answers, and private generator internals are not acceptable substitutes.
