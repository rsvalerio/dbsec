---
id: TASK-0166
title: >-
  READ-8: a detected relocation is logged as a generic transform failure, with
  no column, table or row
status: Done
assignee:
  - TASK-0177
created_date: '2026-08-19 08:31'
updated_date: '2026-08-19 09:37'
labels:
  - code-review-rust
  - observability
dependencies: []
modified_files:
  - crates/proxy/src/rows.rs
  - crates/proxy/src/session.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/rows.rs:766`

**What**: a `DBS3` value that fails to authenticate against its row returns `Error::Decrypt`,
which `is_refusal` excludes, so it reaches the relay loop and is logged as
`tracing::error!(direction, msg_type, error = %e, "transform failed; closing session")`. The
event carries the direction, the frame type, and "decryption failed (wrong key or tampered
data)" — no table, no column, no row key, no position. The identical line is emitted for a
key-rotation mishap or a stale column map.

**Why it matters**: detection whose alarm cannot be attributed is close to no detection. This
is the only externally visible product of row binding, and it does not say which cell fired.
Several other findings in this review additionally make this alarm fire on non-attacks, which
is how an operator learns to filter it.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 The relocation case carries the qualified column name and the row key it failed against into the log event (both non-secret by the envelope docs)
- [x] #2 The event is distinguishable in structured output from an unknown-key or stale-mapping failure
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
A relocation is now attributed. `ReadColumn` carries the qualified `schema.table.column` name as an `Arc<str>` (filled from `column.qualified_name()` in resolve.rs), and `attribute_open_failure` maps a `dbsec_core::Error::Decrypt` raised while a row key was in hand to the new `Error::RowBindingFailed { column, row_key, position }`. AC#1: the relays existing `tracing::error!(direction, msg_type, error = %e, "transform failed; closing session")` event now carries the column, the row key and the result position in `error`. Both are non-secret per the envelope docs; the plaintext is not in reach. AC#2: an unknown-key or any other crypto failure, and a failure with no row key at all, stay `Error::Wire(..)` — a stale mapping is a `StaleColumnMap` refusal on a different event entirely. Implementation substitution to note: the attribution rides the single existing relay event rather than a second `tracing::error!` at the detection site, because logging and propagating the same error would double the entry (ERR-1). Tests: `a_row_bound_value_does_not_open_in_another_row` asserts the variant and its rendered text; `a_crypto_failure_with_no_row_key_is_not_reported_as_a_relocation` pins the discrimination.
<!-- SECTION:NOTES:END -->
