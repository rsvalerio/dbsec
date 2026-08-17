---
id: TASK-0105
title: >-
  Searchable predicates inside operand / EXISTS / projection subqueries are
  never traversed, so they silently match no rows and evade reject mode
status: Done
assignee: []
created_date: '2026-08-14 18:16'
updated_date: '2026-08-17 16:42'
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
**File**: `crates/proxy/src/encrypt.rs:716` (`rewrite_select`), `:1078` (`searchable_operand`).

**What**: `rewrite_select` descends only into FROM-clause derived tables, CTE bodies, and set-operation branches. It never visits `select.projection`, nor subqueries appearing as **expression operands** — scalar subqueries, `EXISTS`, or the inner body of `IN (SELECT ...)`. `searchable_operand` only inspects the two operands of the *outer* predicate; its own comment claims "a searchable column buried in a subquery belongs to that subquery's own traversal", but for these shapes that traversal never runs. `Expr::Exists` is not even an arm in `rewrite_selection`.

**Why it matters**: with `email` searchable, the inner `email = '...'` is left comparing plaintext against the stored `blind_index || envelope`, matching nothing — and it never reaches `unprotected()`, so `on_unprotected = "reject"` does not flag it either. Confirmed parses show the inner predicate sitting untouched inside `Subquery`/`Exists`. Exploits:

- `SELECT * FROM orders WHERE user_id = (SELECT id FROM users WHERE email = 'alice@x.io')` — wrong empty result.
- `SELECT * FROM orders o WHERE EXISTS (SELECT 1 FROM users u WHERE u.email = 'a@b.io')` — silent no-op.
- `SELECT (SELECT id FROM users WHERE email = 'a@b.io') FROM t` — projection subquery never inspected.
- **Data-loss amplifier**: `DELETE FROM t WHERE id NOT IN (SELECT id FROM users WHERE email = 'keep@x.io')` — the subquery silently returns empty, so `NOT IN (empty)` is true for every row and the DELETE removes the whole table. "Silent no rows" is not always fail-safe.

Related shape in the same family: row-wise `WHERE (email, id) IN ((..),(..))` (`Expr::Tuple`) is also silently not rewritten and not flagged (`rewrite_in_list` → `column_ref` `None` → `Ok(false)`).

task-0037 handled the direct `IN`/join/CTE/set-op forms; this residual operand-subquery / `EXISTS` / projection traversal gap is uncovered.

**Fix shape**: give expression operands their own recursive descent so any `Query`/`Select` nested as a scalar subquery, `EXISTS`, `IN (SELECT ...)` body, or projection item is walked by `rewrite_query`/`rewrite_select` under its own scope; add an `Expr::Exists` arm; and route the row-wise `IN` tuple case to `unprotected()`.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 A searchable equality inside a scalar subquery, EXISTS, and IN-(SELECT) body is rewritten to its blind-index form
- [x] #2 A searchable equality inside a projection subquery is rewritten
- [x] #3 Any of the above that cannot be rewritten reaches `unprotected()` and is refused under `reject`
- [x] #4 Row-wise `WHERE (col, ...) IN (...)` over a searchable column is rewritten or flagged, never silently relayed
- [x] #5 A regression test covers the `NOT IN (subquery)` mass-delete amplifier
<!-- AC:END -->
