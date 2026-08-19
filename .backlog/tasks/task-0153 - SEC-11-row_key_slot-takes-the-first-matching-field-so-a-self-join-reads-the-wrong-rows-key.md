---
id: TASK-0153
title: >-
  SEC-11: row_key_slot takes the first matching field, so a self-join reads the
  wrong row's key
status: Done
assignee:
  - TASK-0176
created_date: '2026-08-19 08:28'
updated_date: '2026-08-19 09:43'
labels:
  - code-review-rust
  - security
dependencies: []
modified_files:
  - crates/proxy/src/rows.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/rows.rs:220`

**What**: `row_key_slot` uses `find_map` on `(table_oid, attnum)`. In a self-join —
`SELECT a.id, a.ssn, b.id, b.ssn FROM users a JOIN users b ON ...` — every projection of the
table carries the same `table_oid` and `attnum`, so `b.ssn` is given `a.id`'s slot. The doc
comment defends only the different-table case; RowDescription carries nothing that
distinguishes two instances of the same relation.

**Why it matters**: it fails closed (`Error::Decrypt`), but it kills the session with the same
signal a genuine relocation produces, on legitimate SQL. A detection control that fires on
ordinary queries stops being read as a detection.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 A RowDescription projecting the same (table_oid, attnum) row key more than once is resolved correctly or refused with a distinct client-visible error naming the table
- [x] #2 A test drives a self-join description through Described::new and decrypt_row and asserts the chosen behaviour
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Fixed in wave TASK-0176 (branch code-review/TASK-0176).

`Resolved::row_key_slot` became `row_key_ref`, returning the new
`rows::RowKeyRef` (`Absent` / `Slot` / `Ambiguous`) instead of an
`Option<RowKeySlot>`. A second field matching the declared `(table_oid,
attnum)` no longer resolves to the first: it records `Ambiguous`, and
`decrypt_row` refuses with the new `Error::AmbiguousRowKey { table, column }`.
The variant is in `is_refusal`, so the client gets the same SQLSTATE 42501
ErrorResponse a refused write carries, naming `public.users.id` — and it is
ungated by `on_unprotected`, since the alternative is opening one row's value
against another row's key.

Test: `rows::tests::a_self_join_projecting_the_row_key_twice_is_refused_by_name`
drives `SELECT a.id, a.email, b.id, b.email` through `Described::new` +
`decrypt_row` (AC 2) and through the session, asserting the refusal names the
key column.

Not covered, and filed separately: a self-join that projects the *protected*
column twice while projecting the key once (`SELECT a.id, a.ssn, b.ssn`) is
still resolved to the single key field and still fails as `Error::Decrypt`.
Detecting it would mean refusing `SELECT ssn, ssn FROM users`, which is
legitimate, so it is a separate decision from this one.
<!-- SECTION:NOTES:END -->
