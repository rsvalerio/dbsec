---
id: TASK-0258
title: >-
  SEC-31: an aliased scalar subquery projecting a protected column is seen by
  neither direction, so a mask-only value leaves unmasked
status: Triage
assignee: []
created_date: '2026-08-21 19:55'
labels:
  - code-review-rust
  - security
dependencies: []
modified_files:
  - crates/proxy/src/encrypt/scope.rs
  - crates/proxy/src/encrypt/query.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/encrypt/scope.rs:174`

**What**: `expr_operands` (scope.rs:175-223) has no `Expr::Subquery` arm — `computed_protected_column` deliberately stops at subquery boundaries — and the inner `rewrite_select` sees a bare `body` so raises nothing. PostgreSQL describes a SubLink output with `table_oid = 0`, so the read path cannot mask/decrypt it, and `rows::check_for_stale_mapping` (rows.rs:784) only catches it when the output field is still named like the column. `SELECT (SELECT body FROM notes WHERE id = 1) AS n FROM t` — or any alias — is relayed with the mask-only plaintext (or the raw stored form of an encrypted column) under `reject`, with no signal from either side.

**Why it matters**: same class as TASK-0081 / TASK-0187, reached through a scalar subquery plus alias.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 computed_protected_column reports a projection item that is (or contains) an Expr::Subquery whose own projection resolves to a read-protected column as a ComputedColumn site
- [ ] #2 Tests under both policies for SELECT (SELECT body FROM notes WHERE id = 1) AS n FROM t and SELECT (SELECT email FROM users WHERE id = 1) AS e FROM t
<!-- AC:END -->
