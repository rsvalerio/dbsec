---
id: TASK-0104
title: >-
  Row-wise UPDATE SET (a, b) = (...) tuple assignment writes plaintext to a
  protected column and is not an on_unprotected site
status: Triage
assignee: []
created_date: '2026-08-14 18:16'
labels:
  - security-review
  - security
  - sql-rewrite
dependencies: []
modified_files:
  - crates/proxy/src/encrypt.rs
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/encrypt.rs:668` (`seal_assignments`).

**What**: `seal_assignments` is the single choke point for every `UPDATE` and every `INSERT ... ON CONFLICT DO UPDATE`. Its loop opens with:

```rust
let AssignmentTarget::ColumnName(column) = target else { continue };
```

sqlparser 0.53 parses PostgreSQL's row-wise assignment `SET (col1, col2) = (v1, v2)` as `AssignmentTarget::Tuple(...)`, which this `else { continue }` silently drops. `AssignmentTarget::Tuple` is matched nowhere else in the file (only the `use` import at `encrypt.rs:106`). The parse was confirmed against the exact sqlparser version the proxy pins:

```
UPDATE users SET (email, id) = ('alice@secret.test', 5)
 => Assignment { target: Tuple([email, id]), value: Tuple([...]) }
```

**Why it matters**: `UPDATE users SET (email, id) = ('alice@secret.test', 5)` — with `email` protected — is skipped entirely: no seal, no blind index, and critically **no `unprotected()` call**. The plaintext lands at rest in the protected column *even under `on_unprotected = "reject"`*, because the statement never reaches the reject decision. This is a true silent bypass of the "never at rest in plaintext" invariant via standard, valid PostgreSQL syntax, with zero operator-visible signal. Reachable as `SET (email) = ('x')`, `SET (email, id) = (SELECT ...)`, and inside `ON CONFLICT (id) DO UPDATE SET (email, ...) = (...)` (same shared function). This is the most severe finding of the 2026-08-14 review.

**Fix shape**: add an `AssignmentTarget::Tuple` arm to `seal_assignments` that pairs each tuple target ident with the corresponding value element and seals protected ones (handling the `= (subquery)` and arity-mismatch cases by routing to `unprotected()`); at minimum, any tuple target that touches a protected column must reach `self.unprotected(...)` so `reject` refuses it rather than relaying plaintext.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 `UPDATE t SET (protected, other) = (v1, v2)` seals the protected element (blind index included when searchable)
- [ ] #2 The same shape inside `INSERT ... ON CONFLICT DO UPDATE` is sealed
- [ ] #3 A tuple target that cannot be sealed (subquery source, arity mismatch) is an `on_unprotected` site refused under `reject`
- [ ] #4 A regression test asserts plaintext never reaches the backend for a tuple-assignment write under both `warn` and `reject`
<!-- AC:END -->
