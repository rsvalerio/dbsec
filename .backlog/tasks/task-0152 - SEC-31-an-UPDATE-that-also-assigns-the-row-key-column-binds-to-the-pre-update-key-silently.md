---
id: TASK-0152
title: >-
  SEC-31: an UPDATE that also assigns the row key column binds to the pre-update
  key, silently
status: Done
assignee:
  - TASK-0173
created_date: '2026-08-19 08:28'
updated_date: '2026-08-19 09:43'
labels:
  - code-review-rust
  - security
dependencies: []
modified_files:
  - crates/proxy/src/encrypt/seal.rs
  - crates/proxy/src/encrypt/mod.rs
  - crates/proxy/src/encrypt/unprotected.rs
  - README.md
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/encrypt/seal.rs:181`

**What**: nothing checks whether the assignment list writes the row key column itself.
`UPDATE users SET ssn = 'x', id = 99 WHERE id = 7` derives `RowKeySource::Literal("7")`, seals
`ssn` against `7`, and the server then moves the row to `id = 99`. Same for
`ON CONFLICT DO UPDATE SET id = ...`. No `unprotected()` call, so it is silent under `reject`
as well as `warn`. Both the single-column and `AssignmentTarget::Tuple` paths are affected.

The neighbouring case — an UPDATE that changes only the row key, orphaning already-sealed
siblings — is inherent to row binding, but is not stated in README or the envelope docs either.

**Why it matters**: silent, permanent corruption of the protected value, surfacing later as a
`Decrypt`-class false tamper alarm that kills the session.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 An assignment list on a row-bound table targeting the row key column routes through an Unprotected site; refused under reject
- [x] #2 Both the single-column and tuple assignment paths are covered
- [x] #3 README states that the row key of a row holding protected values must not be updated
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Fixed in code-review/TASK-0173.

New `Unprotected::RowKeyReassigned { table, column }` site
(crates/proxy/src/encrypt/unprotected.rs), kept apart from `RowKeyMissing`
because the statement *does* name a row — the row the values are being moved
out of — so the remedy differs: split the key change and the protected write
into separate statements rather than supply a key.

`assigns_column` (crates/proxy/src/encrypt/seal.rs) checks both
`AssignmentTarget::ColumnName` and `AssignmentTarget::Tuple`, and both
`update_row` (UPDATE) and `conflict_row` (ON CONFLICT DO UPDATE /
ON DUPLICATE KEY UPDATE) return `AssignmentRow::Reassigned` when the list
writes the row key. `row_of` turns that into the site, so it fires only where
a protected value would actually have been sealed — refused under `reject`,
warned and left unsealed under `warn`.

README: the `row_key` constraint list gained "The row key is immutable once a
row holds a protected value", which states both the enforced case and the
neighbouring one the proxy cannot see (changing the key alone orphans values
already stored in that row), plus an "Upserts conflict on the key" bullet and
a note to qualify the key in `UPDATE ... FROM`.

Test (crates/proxy/src/rows.rs):
`an_update_that_also_assigns_the_row_key_is_refused` covers the single-column
UPDATE, the row-wise `SET (id, email) = (...)` tuple, and the conflict-action
form.

Correction to the note above: `QueryRewriter::row_of` does not leave the value unsealed
under `warn`. It reports the site and then falls back to `RowKeySource::None` — cell-only
binding, the protection the table had before it declared a row key. Dropping to plaintext
would be a downgrade dressed as a fix. Under `reject` the report is the answer and nothing
is written. The `INSERT ... VALUES` path still returns unsealed in the same situation;
that asymmetry is filed as TASK-0184.
<!-- SECTION:NOTES:END -->
