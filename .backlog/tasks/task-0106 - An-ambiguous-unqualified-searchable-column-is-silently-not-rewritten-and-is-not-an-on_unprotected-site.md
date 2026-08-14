---
id: TASK-0106
title: >-
  An ambiguous unqualified searchable column is silently not rewritten and is
  not an on_unprotected site
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
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/encrypt.rs:1032` (`TableScope::resolve`).

**What**: when an unqualified searchable column matches more than one protected table in scope, `resolve` returns `None` after only a `tracing::warn!`. Back in `rewrite_selection`, both `column_ref` calls then return `None`, so the predicate is routed to `unsupported_predicate` → `searchable_operand`, which also calls `column_ref` (again `None`), concludes there is no searchable operand, and returns `Ok(false)`. Net effect: the equality is left comparing plaintext against the stored `blind_index || envelope` (matching no rows) and, because it never reaches `self.unprotected(...)`, it is **not refused under `reject`** — only a log line is emitted.

**Why it matters**: two protected tables that both carry a searchable `email`, joined —

```sql
SELECT * FROM users u JOIN accounts a ON u.id = a.uid WHERE email = 'a@b.io'
```

— silently matches nothing and emits no ErrorResponse even under `on_unprotected = "reject"`. A query the operator believes is protected returns wrong results with no error surface. This is the same "silent skip of a protected-relevant construct that never reaches the reject decision" class as task-0104/0105.

**Fix shape**: when an unqualified name is ambiguous across protected tables in scope, treat it as an `on_unprotected` site (a dedicated `Unprotected::AmbiguousColumn` variant) so it warns under `warn` and refuses under `reject`, rather than degrading to a plaintext comparison.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 An ambiguous unqualified searchable column reaches `unprotected()` instead of returning `Ok(false)`
- [ ] #2 Under `reject` the statement is refused with an ErrorResponse; under `warn` it is logged
- [ ] #3 A test covers two protected tables sharing a searchable column joined in one query
<!-- AC:END -->
