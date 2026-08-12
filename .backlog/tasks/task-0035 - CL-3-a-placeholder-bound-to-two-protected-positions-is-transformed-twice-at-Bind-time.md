---
id: TASK-0035
title: >-
  CL-3: a placeholder bound to two protected positions is transformed twice at
  Bind time
status: Done
assignee:
  - TASK-0050
created_date: '2026-08-11 19:34'
updated_date: '2026-08-12 16:54'
labels:
  - code-review-rust
  - correctness
  - encrypt-path
dependencies: []
modified_files:
  - crates/proxy/src/encrypt.rs
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/encrypt.rs:123-148`

**What**: `ParamTransforms` is a `Vec<(usize, ParamAction)>` and the Bind handler applies **every** entry to the same mutable value in sequence:

```rust
for (index, action) in params {
    let Some(Some(value)) = values.get_mut(*index) else { continue };
    let (replacement, wire) = match action { ... };
    *value = ...;
}
```

Nothing guarantees an index appears at most once. `rewrite_statement`'s `Statement::Update` arm pushes actions from two independent walks over the same statement — first the assignments (`encrypt.rs:248` → `seal_expr` → `ParamAction::Seal`), then the WHERE clause (`encrypt.rs:254` → `rewrite_selection` → `rewrite_equality` → `ParamAction::SearchIndex`, `encrypt.rs:427`). A statement that uses one placeholder in both roles produces two entries for the same index:

```sql
UPDATE users SET email = $1 WHERE email = $1
```
→ `params = [(0, Seal), (0, SearchIndex)]`

At Bind the value is sealed first, and the blind index is then computed over the **ciphertext** rather than the plaintext. The rewritten WHERE (`substring(email from 1 for 32) = $1`) can never match any row, and the UPDATE silently affects zero rows.

The same shape occurs on the write path alone when one parameter feeds two protected columns, e.g. `INSERT INTO users (email, email_backup) VALUES ($1, $1)` with both columns protected: `[(0, Seal), (0, Seal)]` double-seals, storing `seal(seal(plaintext))`. That row is unrecoverable through the read path — a single `open` yields the inner ciphertext, not the plaintext.

**Why it matters**: Both outcomes are silent. The double-seal is permanent data corruption written by a statement the client had every reason to believe succeeded; the seal-then-index case is a wrong answer (`rows_affected = 0`) with no error to distinguish it from "no such row". Reusing one placeholder across positions is ordinary SQL that every driver and ORM emits, so this is not an exotic input. The precondition "each parameter index is acted on at most once" exists only as an accident of how the two walks happen to be written, and is documented nowhere.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 ParamTransforms cannot hold two actions for the same parameter index — the type or the insertion path rejects or merges the duplicate rather than applying both
- [x] #2 UPDATE users SET email = $1 WHERE email = $1 seals the assignment and indexes the WHERE from the same plaintext, and the update matches the intended row
- [x] #3 An INSERT binding one placeholder to two protected columns seals the plaintext once per column, and both values open back to the plaintext
- [x] #4 A test covers both shapes (one param, two protected positions) for the simple and extended protocols
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
`ParamTransforms` is now a type (in `portal.rs`) whose only insertion path is `record(index, action)`: it collapses a repeat of the same action for one placeholder and returns `Error::ConflictingParameter` for a conflicting one, so a Bind value is transformed at most once.

AC#1: `record` is the only way in; `push` is gone.
AC#2: `UPDATE users SET email = $1 WHERE email = $1` is now refused rather than sealed-then-indexed-over-the-ciphertext. The extended protocol cannot serve both roles from one wire value — a Bind carries one value per placeholder — so the honest answer is an error, not a rewrite that silently matches no row. The simple-protocol form of the same statement has two independent literals and still works, and is asserted to.
AC#3: the multi-row `VALUES ($1), ($1)` case is collapsed to one seal and asserted to open back to the plaintext.
AC#4: `encrypt.rs::a_placeholder_in_two_protected_roles_is_refused_rather_than_transformed_twice` and `a_placeholder_reused_for_one_column_is_sealed_once_not_twice` cover both shapes in both protocols; `portal.rs::one_placeholder_cannot_carry_two_conflicting_actions` covers the type directly.
<!-- SECTION:NOTES:END -->
