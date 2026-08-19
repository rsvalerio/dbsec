---
id: TASK-0146
title: >-
  SEC-31: INSERT ... ON CONFLICT DO UPDATE seals a row-bound column with no row
  key and no signal
status: Done
assignee:
  - TASK-0173
created_date: '2026-08-19 08:26'
updated_date: '2026-08-19 09:43'
labels:
  - code-review-rust
  - security
dependencies: []
modified_files:
  - crates/proxy/src/encrypt/mod.rs
  - crates/proxy/src/encrypt/seal.rs
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**Severity: critical** (filed as High — the backlog has no critical tier).

**File**: `crates/proxy/src/encrypt/mod.rs:1010`

**What**: `rewrite_insert` builds the conflict action's scope as
`AssignmentScope { row: RowKeySource::None, columns, sealed }` — hardcoded — even though
`rewrite_insert_values` resolved a `ResolvedRowKey` for the same table a few lines above.
`seal_assignments` then takes the `RowKeySource::None` arm and writes a `DBS2` cell-only
envelope. No `unprotected()` call is reached, so there is no warning under `warn` and **no
refusal under `reject`**. The same statement writes `DBS3` for the inserted row and `DBS2`
for the conflict-updated row. `OnInsert::DuplicateKeyUpdate` has the same defect.

`SET ssn = EXCLUDED.ssn` is safe (skipped by the sealed-values whitelist), which is why the
gap is easy to miss — it is the `SET ssn = $2` form that breaks.

**Why it matters**: `INSERT ... ON CONFLICT (id) DO UPDATE SET ssn = $2` is the canonical
PostgreSQL upsert. The operator declares `row_key`, config validation passes, the log says
"row key resolved; this table's encrypted values are bound to their row", and every
upsert-written value is nonetheless relocatable between rows. This is exactly the silent
under-protection the feature exists to remove, and `SealTarget`'s own doc names it: "a
caller that had the transform but forgot the row would seal a row-bound column with
cell-only binding". The row key *is* derivable here — `ON CONFLICT (id)` means the
conflicting row carries the key the VALUES row proposed.

Found independently by two reviewers and confirmed at source.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 The conflict action carries the RowKeySource the VALUES list derived, or routes through Unprotected::RowKeyMissing when it cannot be derived
- [x] #2 A test asserts the conflict-updated column's stored bytes start with MAGIC_V3, or that the statement is refused under reject
- [x] #3 OnInsert::DuplicateKeyUpdate takes the same path, and SET col = EXCLUDED.col stays passed through
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Fixed in code-review/TASK-0173.

`rewrite_insert` no longer hardcodes `RowKeySource::None` for the conflict
action. `QueryRewriter::conflict_row` (crates/proxy/src/encrypt/seal.rs) derives
the action's row from the `VALUES` row, but only where the derivation is sound:
`ON CONFLICT (<row key>)` is the one target that proves the conflicting row
carries the key the VALUES row proposed. `ON CONFLICT (<other unique column>)`,
`ON CONFLICT ON CONSTRAINT`, `ON DUPLICATE KEY UPDATE` and a multi-row VALUES
list all route through `Unprotected::RowKeyMissing` instead.

The gap is carried as `AssignmentRow` rather than reported where it is found,
so a conflict action that assigns no protected column (`SET hits = hits + 1`)
is not refused: `QueryRewriter::row_of` reports it at the one point where a
protected value is about to be sealed.

`SET col = EXCLUDED.col` stays passed through on `ON CONFLICT (id)`. It is now
refused on any other conflict target: the whitelisted value is sealed against
the *inserted* row's key, so it is only the right ciphertext for the
conflicting row when the two share a key. That reorder is in
`seal_assignments` / `seal_tuple_assignment`.

Tests (crates/proxy/src/rows.rs):
`an_upsert_binds_its_conflict_action_to_the_row_it_conflicts_on` (asserts both
literals start with MAGIC_V3 and the conflict action's opens under row key 7),
`an_upsert_that_cannot_name_its_conflicting_row_is_refused` (all four gap
shapes, incl. `ON DUPLICATE KEY UPDATE`), and
`excluded_is_re_stored_only_where_the_conflicting_row_shares_the_key`.

Correction to the note above: `QueryRewriter::row_of` does not leave the value unsealed
under `warn`. It reports the site and then falls back to `RowKeySource::None` — cell-only
binding, the protection the table had before it declared a row key. Dropping to plaintext
would be a downgrade dressed as a fix. Under `reject` the report is the answer and nothing
is written. The `INSERT ... VALUES` path still returns unsealed in the same situation;
that asymmetry is filed as TASK-0184.
<!-- SECTION:NOTES:END -->
