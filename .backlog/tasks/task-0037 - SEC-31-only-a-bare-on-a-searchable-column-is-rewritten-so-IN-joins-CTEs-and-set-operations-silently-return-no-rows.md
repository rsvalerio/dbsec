---
id: TASK-0037
title: >-
  SEC-31: only a bare = on a searchable column is rewritten, so IN, joins, CTEs
  and set operations silently return no rows
status: In Progress
assignee:
  - TASK-0049
created_date: '2026-08-11 19:35'
updated_date: '2026-08-12 16:25'
labels:
  - code-review-rust
  - security
  - correctness
  - encrypt-path
dependencies: []
modified_files:
  - crates/proxy/src/encrypt.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/encrypt.rs:374-403`, `crates/proxy/src/encrypt.rs:258-266`

**What**: `rewrite_selection` recognises exactly one comparison shape and one container set:

```rust
match expr {
    Expr::BinaryOp { left, op: BinaryOperator::Eq, right } => ...,
    Expr::BinaryOp { left, op: BinaryOperator::And | BinaryOperator::Or, right } => ...,
    Expr::Nested(inner) => ...,
    Expr::UnaryOp { op: UnaryOperator::Not, expr: inner } => ...,
    _ => Ok(false),
}
```

and `Statement::Query` only descends when the top-level body is a plain `SetExpr::Select`, passing only `select.selection` (the WHERE clause) to it.

Everything else falls into `_ => Ok(false)` with no warning:

| Shape | Why it is missed |
|---|---|
| `WHERE email IN ('a@x','b@x')` | `Expr::InList` is not matched |
| `WHERE email = ANY($1)` | `Expr::AnyOp` is not matched |
| `FROM a JOIN b ON a.email = b.email` | `join_operator`'s constraint is never passed to `rewrite_selection`; only `select.selection` is |
| `WITH hits AS (SELECT ... WHERE email = $1) SELECT * FROM hits` | the CTE's inner query body is never visited |
| `SELECT ... WHERE email = $1 UNION SELECT ...` | `query.body` is `SetExpr::SetOperation`, so the arm returns immediately |
| `HAVING` / `ON CONFLICT` / correlated subquery predicates | never reached |

In every one of these the client's plaintext is compared directly against the stored form — `blind_index (32B) || envelope` for a searchable column — so the predicate is false for every row. The query succeeds and returns an empty result set.

**Why it matters**: This is the fail-open case the design is otherwise careful to avoid. `rows.rs:1-5` states crypto errors fail the session rather than passing ciphertext through, and `TableScope::resolve` (`encrypt.rs:344-347`) even warns when it declines to rewrite an *ambiguous* column. But the far more common case — a supported column referenced through an unsupported operator — produces no error, no warning, and no log line at all. The client cannot distinguish "no such user" from "the proxy did not understand your query", which is the worst possible failure mode for a search: an authorization check written as `SELECT 1 FROM users WHERE email IN (...)` fails open into "not found", and a `DELETE ... WHERE email IN (...)` silently deletes nothing. `IN` with a bound list is the single most common way an ORM expresses a multi-value lookup, so the gap is squarely on the mainline path, not at the edges.

At minimum the proxy must *notice*: any reference to a searchable column that reaches a comparison the rewriter cannot handle should warn, and under a strict setting ([[task-0001]]) should be an error. Extending coverage to `IN`, `= ANY`, join constraints and nested query bodies is the fuller fix.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 A searchable column referenced in a predicate the rewriter cannot handle produces a warning naming the column and the unsupported shape, instead of silently passing through
- [ ] #2 IN and = ANY over a searchable column are rewritten to blind-index comparisons, for both literal lists and bound parameters
- [x] #3 Join ON constraints, CTE bodies and set-operation branches are traversed by the same rewrite that handles the top-level WHERE, or are explicitly warned about
- [x] #4 Tests cover IN, = ANY, a JOIN ON equality, a CTE and a UNION over a searchable column, asserting either a correct rewrite or the warning
- [x] #5 The module docs state which query shapes support searchable equality and what happens to the rest
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Landed in TASK-0049 except AC #2's bound-array half.

Done: unhandled predicates over a searchable column are now an `Unprotected::Predicate`
site (warn by default, ErrorResponse under `on_unprotected = "reject"`) instead of a
silent `Ok(false)`; `IN (<literals>)`, `IN ($1, $2)` and `= ANY(ARRAY[...])` rewrite to
blind-index prefix matches; traversal now covers JOIN ON constraints, CTE bodies,
set-operation branches, derived-table subqueries and HAVING as well as WHERE; the module
docs state which shapes are supported and what happens to the rest.

Left open: AC #2 asks for `= ANY` over *bound parameters* too. `= ANY($1)` passes the
whole list as one array parameter, so rewriting it needs a Bind-time array codec (text
and binary formats) that decodes, indexes each element and re-encodes as bytea[]. That
was deliberately not attempted here: a half-tested codec produces a *valid* query that
matches the wrong rows, which is worse than the refusal it would replace. Filed as
TASK-0062 (Triage).
<!-- SECTION:NOTES:END -->
