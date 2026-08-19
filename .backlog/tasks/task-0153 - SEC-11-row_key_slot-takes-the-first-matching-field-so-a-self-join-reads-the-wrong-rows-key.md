---
id: TASK-0153
title: >-
  SEC-11: row_key_slot takes the first matching field, so a self-join reads the
  wrong row's key
status: To Do
assignee:
  - TASK-0176
created_date: '2026-08-19 08:28'
updated_date: '2026-08-19 09:01'
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
- [ ] #1 A RowDescription projecting the same (table_oid, attnum) row key more than once is resolved correctly or refused with a distinct client-visible error naming the table
- [ ] #2 A test drives a self-join description through Described::new and decrypt_row and asserts the chosen behaviour
<!-- AC:END -->
