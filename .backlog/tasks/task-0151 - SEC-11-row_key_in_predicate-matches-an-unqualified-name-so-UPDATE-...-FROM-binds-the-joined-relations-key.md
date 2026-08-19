---
id: TASK-0151
title: >-
  SEC-11: row_key_in_predicate matches an unqualified name, so UPDATE ... FROM
  binds the joined relation's key
status: Done
assignee:
  - TASK-0173
created_date: '2026-08-19 08:28'
updated_date: '2026-08-19 09:40'
labels:
  - code-review-rust
  - security
dependencies: []
modified_files:
  - crates/proxy/src/encrypt/seal.rs
  - crates/proxy/src/encrypt/scope.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/encrypt/seal.rs:52`

**What**: the `Eq` arm compares `column_name(e)` against the row key name, and `column_name`
reduces a `CompoundIdentifier` to its **last** ident, discarding the qualifier. `Statement::Update`
carries a `from`, so `UPDATE users u SET ssn = 'x' FROM audit a WHERE a.id = 1 AND u.id = 99`
matches `a.id` first (the `And` arm tries `left` via `.or_else`) and seals against row key `1`
while the statement writes row `99`. No scope resolution is done on this predicate, unlike
every other predicate walk in the module.

**Why it matters**: the value is sealed against a row it does not land in, so it is permanently
unreadable and surfaces at read time as `Error::Decrypt` — a false tamper alarm and a killed
session. It is attacker-influenceable: anyone who can shape the FROM relation or its predicate
chooses which key the proxy binds.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 An unqualified ident is accepted only when unambiguous in scope; a qualified one only when the qualifier names the target table or its alias
- [x] #2 A test asserts UPDATE users u SET ssn = ... FROM audit a WHERE a.id = 1 AND u.id = 99 binds 99 or is signalled, never 1
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Fixed in code-review/TASK-0173.

`row_key_in_predicate` (crates/proxy/src/encrypt/seal.rs) no longer reduces an
operand to its last ident. The new `names_row_key` helper resolves a qualified
reference against the target relation via `ScopedTable::matches` (so `u.id`
matches `UPDATE users u` and `a.id` does not), and accepts a bare ident only
when the statement joins nothing else — `joined` is true for `UPDATE ... FROM`
and for any join sqlparser attached to the target. The catalog holds columns
for protected tables only, so with a join in scope the proxy cannot prove a
bare `id` belongs to the target; that case is now signalled through
`Unprotected::RowKeyMissing` rather than guessed.

`ScopedTable::matches` was widened from private to `pub(super)`.

Tests (crates/proxy/src/rows.rs):
`an_update_from_binds_the_target_relations_row_key_not_the_joined_ones` asserts
`UPDATE users u SET email = ... FROM audit a WHERE a.id = 1 AND u.id = 99`
seals against 99 and that the stored bytes do not open under key 1;
`an_unqualified_row_key_is_refused_once_the_statement_joins` covers the
unqualified form.
<!-- SECTION:NOTES:END -->
