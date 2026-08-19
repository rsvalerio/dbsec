---
id: TASK-0152
title: >-
  SEC-31: an UPDATE that also assigns the row key column binds to the pre-update
  key, silently
status: To Do
assignee:
  - TASK-0173
created_date: '2026-08-19 08:28'
updated_date: '2026-08-19 09:01'
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
- [ ] #1 An assignment list on a row-bound table targeting the row key column routes through an Unprotected site; refused under reject
- [ ] #2 Both the single-column and tuple assignment paths are covered
- [ ] #3 README states that the row key of a row holding protected values must not be updated
<!-- AC:END -->
