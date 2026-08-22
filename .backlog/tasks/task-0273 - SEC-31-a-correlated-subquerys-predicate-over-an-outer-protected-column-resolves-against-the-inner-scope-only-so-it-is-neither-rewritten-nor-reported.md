---
id: TASK-0273
title: >-
  SEC-31: a correlated subquery's predicate over an outer protected column
  resolves against the inner scope only, so it is neither rewritten nor reported
status: Triage
assignee: []
created_date: '2026-08-22 00:45'
labels:
  - code-review-rust
  - security
dependencies: []
modified_files:
  - crates/proxy/src/encrypt/query.rs
  - crates/proxy/src/encrypt/predicate.rs
  - crates/proxy/src/encrypt/scope.rs
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/encrypt/query.rs:57`

**What**: rewrite_nested_queries (predicate.rs:86) hands every Expr::Subquery / Exists / InSubquery to rewrite_query (query.rs:57), which builds its scope from the nested select's own FROM (query.rs:95 `self.scope(&select.from)`) and never receives the enclosing scope. A correlated reference to an outer relation — `SELECT * FROM users u WHERE EXISTS (SELECT 1 FROM orders o WHERE o.user_id = u.id AND u.email = 'a@x')`, or `UPDATE users u SET flag = 1 WHERE (SELECT count(*) FROM orders o WHERE u.email = $1) > 0` — reaches rewrite_selection with `u` absent from the scope, so column_ref returns None and unsupported_predicate's protected_operand (scope.rs) also finds nothing: no index rewrite, no Unprotected site. TASK-0037 (Done) listed 'correlated subquery predicates | never reached'; the traversal now reaches them but still resolves them against the wrong scope, so the hole is still present.

**Why it matters**: The client's plaintext is compared against `blind_index || envelope`, matching no row, and `reject` does not refuse it. An EXISTS/NOT EXISTS or scalar-subquery authorization check over a searchable column silently fails open to 'not found' / 'true for every row' (NOT EXISTS), the exact failure the module doc calls unsafe.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 rewrite_query accepts (or rewrite_nested_queries passes) the enclosing TableScope so a nested select's predicates resolve against inner tables first and outer tables second, per PostgreSQL name resolution
- [ ] #2 A correlated `u.email = <literal|$n>` in an EXISTS, scalar or IN subquery is rewritten to the blind-index prefix match; an unrewritable correlated comparison over a protected column raises Unprotected::Predicate / UnindexedPredicate and is refused under reject
- [ ] #3 Unit tests cover EXISTS, scalar subquery in WHERE, scalar subquery in projection and a correlated reference from UPDATE/DELETE, asserting rewrite under warn and refusal under reject
<!-- AC:END -->
