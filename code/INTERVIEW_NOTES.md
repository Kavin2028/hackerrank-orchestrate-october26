# Architecture and interview notes

The agent starts by interpreting whether request_text authorizes deletion. Non-deletion requests produce NOT_APPLICABLE and no steps. Current identities and historical changes supply exact aliases, filtered by when the information was available. Stable references and catalog relationships connect records without trusting operation success as proof of state.

Adapters extract JSON records, SQL tables, correlated service logs, text handovers, PDF text, and screenshot OCR. Every observation carries resource, system, category, observation time, capture time, evidence ID, and copy scope. The audit excludes later evidence. A primary readback cannot clear a surviving replica; each copy has an independent timeline before logical-resource aggregation. Batch inventories cannot establish absence for unrelated subjects.

Policy selects deletion, redaction, anonymization, or retention. Stable tombstone references are allowed while direct identifiers and hashes are prohibited. Active flows and unsafe restore paths receive their own findings and actions. Findings, remediation, and verification use the allowed vocabulary and deterministic required order. Future actions have blank evidence IDs. Missing required retained records cause INCOMPLETE and an explicit diagnostic because the vocabulary cannot express recovery.

The evaluator alone reads public sample answers and measures status, exact steps, positional fields, and ordered sequences. Independent regressions exercise time cutoffs, replica drift, retention, authorization, scoped absence, identity history, and recreation paths. A clean extracted package must reproduce the 518-row output with fresh OCR. The final-run report distinguishes local OCR and deterministic inference from development-model usage; the pipeline makes no generative API calls.

Be candid about limitations: public expected-answer equivalence has not been achieved, hidden accuracy is unknown, unlinked anonymous resources cannot be assigned guessed identities, and documented contract ambiguities remain. Explain the evidence needed to resolve these rather than presenting schema validity as correctness.
