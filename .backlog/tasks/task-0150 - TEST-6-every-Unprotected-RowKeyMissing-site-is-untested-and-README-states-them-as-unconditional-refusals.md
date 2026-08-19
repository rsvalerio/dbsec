---
id: TASK-0150
title: >-
  TEST-6: every Unprotected::RowKeyMissing site is untested, and README states
  them as unconditional refusals
status: Done
assignee:
  - TASK-0174
created_date: '2026-08-19 08:27'
updated_date: '2026-08-19 10:00'
labels:
  - code-review-rust
  - test-coverage
dependencies: []
modified_files:
  - crates/proxy/src/encrypt/seal.rs
  - crates/proxy/src/encrypt/mod.rs
  - crates/proxy/src/rows.rs
  - README.md
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/encrypt/seal.rs:140`

**What**: row binding added three write-path sites where a statement cannot name its row —
`seal.rs:140` (INSERT without the key in its column list), `seal.rs:157` (row-key value not a
literal or parameter), `mod.rs:811` (UPDATE whose WHERE does not pin one row). `RowKeyMissing`
appears **only** in production code and never in a test. The single row-binding fixture
(`rows.rs:981 row_bound_session`) is used by two tests, both supplying the happy path. The
read-path counterpart is in the same state: `row_bound_description()` always projects both
fields, so no test produces a result set that omits the row key.

Worse, all three sites route through `self.unprotected(...)`, whose default is
`OnUnprotected::Warn` — so **by default the statement is relayed with the plaintext
unsealed**, not refused. README says the opposite, unconditionally: "each constraint is a
refusal rather than a silent degradation ... `WHERE dept = 'x'` is refused."
`row_bound_session()` also hard-codes `Reject`, so even a new test there would exercise only
the non-default half.

**Why it matters**: the highest-value gap in the diff. A feature whose entire point is that a
value cannot be sealed unbound has three fail-open paths and not one test, while the
documentation promises behaviour the default configuration does not deliver. A refactor that
dropped the `key_position` check would turn every row-bound INSERT into a plaintext write and
the suite would stay green.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 A test per site drives it under Warn (relayed, exactly one warning naming table and row key) and under Reject (ErrorResponse text); row_bound_session is parameterised by policy
- [x] #2 A read-path test omits the row-key field from the RowDescription, feeds a DBS3 value, and asserts RefuseAndClose with the 42501 ErrorResponse
- [x] #3 README either says these are reported through on_unprotected (warning by default) or the sites stop consulting the policy; tests pin whichever is chosen
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
AC #3 resolved by documenting the write-path row-binding constraints as on_unprotected sites (warning by default) in README, and pinning both modes in rows::tests::every_site_that_cannot_name_the_row_reports_itself_in_both_modes.
<!-- SECTION:NOTES:END -->
