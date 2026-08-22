---
id: TASK-0253
title: >-
  SEC-31: a protected column reached through any wrapping expression in a
  predicate is neither rewritten nor reported
status: Triage
assignee: []
created_date: '2026-08-21 19:55'
labels:
  - code-review-rust
  - security
dependencies: []
modified_files:
  - crates/proxy/src/encrypt/scope.rs
  - crates/proxy/src/encrypt/predicate.rs
  - crates/proxy/src/encrypt/query.rs
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/encrypt/scope.rs:334`, `crates/proxy/src/encrypt/predicate.rs:316`

**What**: `protected_operand`/`ambiguous_operand` look exactly one level deep: the operand must be an `Identifier`/`CompoundIdentifier` (or a `Tuple` of them):
```rust
// scope.rs:381
let transform = column_ref(scope, operand)?;
// predicate.rs:329
let Some((column, searchable)) = protected_operand(expr, scope) else { return Ok(false) };
```
Any wrapper on the column side — `lower(email) = 'x'`, `email::text = 'x'`, `(email) = 'x'`, `coalesce(email, '') = 'x'`, `email || '' = 'x'` — resolves to `ColumnResolution::Unknown`, so `rewrite_equality` is skipped and `unsupported_predicate` returns `Ok(false)` with no site. Likewise any equality nested in a non-comparison node — `WHERE CASE WHEN email = 'x' THEN ... END`, `(email = 'x') IS TRUE`, `coalesce(email = 'x', false)`, `count(*) FILTER (WHERE email = 'x')`, `ORDER BY email = 'x'` — hits `rewrite_selection`'s `_ => self.unsupported_predicate(...)` arm (predicate.rs:208) whose `predicate_operands` (scope.rs:334-348) returns `None` for `Case`/`IsTrue`/`Function`. The read-path walk `expr_operands` (scope.rs:174) already descends these shapes; the predicate walk does not. mod.rs:61-64 promises "anything else that mentions a protected column ... is an Unprotected site".

**Why it matters**: the comparison is relayed comparing plaintext against `blind_index || envelope`: matches no row, inverted (`<>`, `NOT IN`) matches every row, and `reject` does not fire. `DELETE FROM users WHERE lower(email) <> 'x'` deletes the table.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Under reject, every predicate whose operand contains a reference to a protected column at any depth (function arg, cast, nested parens, CASE branch, FILTER clause, ORDER/GROUP BY) is refused with Predicate/UnindexedPredicate/AmbiguousColumn; under warn it emits the corresponding warning
- [ ] #2 A test table covering lower(email) = 'x', email::text = 'x', (email) = 'x', CASE WHEN email = 'x', (email = 'x') IS TRUE, count(*) FILTER (WHERE email = 'x') and ORDER BY email = 'x' asserts refusal/warning and no silent relay
<!-- AC:END -->
