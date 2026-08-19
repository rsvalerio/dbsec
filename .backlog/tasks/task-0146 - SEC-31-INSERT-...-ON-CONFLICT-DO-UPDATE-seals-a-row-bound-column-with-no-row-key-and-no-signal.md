---
id: TASK-0146
title: >-
  SEC-31: INSERT ... ON CONFLICT DO UPDATE seals a row-bound column with no row
  key and no signal
status: To Do
assignee:
  - TASK-0173
created_date: '2026-08-19 08:26'
updated_date: '2026-08-19 09:01'
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
- [ ] #1 The conflict action carries the RowKeySource the VALUES list derived, or routes through Unprotected::RowKeyMissing when it cannot be derived
- [ ] #2 A test asserts the conflict-updated column's stored bytes start with MAGIC_V3, or that the statement is refused under reject
- [ ] #3 OnInsert::DuplicateKeyUpdate takes the same path, and SET col = EXCLUDED.col stays passed through
<!-- AC:END -->
