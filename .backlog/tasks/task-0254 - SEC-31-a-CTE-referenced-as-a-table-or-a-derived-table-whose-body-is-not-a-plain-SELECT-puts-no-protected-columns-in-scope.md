---
id: TASK-0254
title: >-
  SEC-31: a CTE referenced as a table, or a derived table whose body is not a
  plain SELECT, puts no protected columns in scope
status: Triage
assignee: []
created_date: '2026-08-21 19:55'
labels:
  - code-review-rust
  - security
dependencies: []
modified_files:
  - crates/proxy/src/encrypt/query.rs
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/encrypt/query.rs:244`, `crates/proxy/src/encrypt/query.rs:294`

**What**:
```rust
// query.rs:244-245
TableFactor::Table { name, alias, .. } => {
    let Some((columns, read_columns)) = self.scoped_table(name)? else { continue };
// query.rs:294
let SetExpr::Select(select) = subquery.body.as_ref() else { return Ok(None) };
```
`scope_of` resolves a `TableFactor::Table` only against the catalog, so a CTE name (`WITH u AS (SELECT * FROM users) SELECT id FROM u WHERE email = 'a@b.io'`) resolves to nothing; `derived_scope` returns `None` for a derived table whose body is a set operation or parenthesised query (`FROM (SELECT email FROM users UNION ALL SELECT email FROM users) s WHERE s.email = 'x'`). The outer predicate resolves to `Unknown` and is relayed unrewritten and unreported (TASK-0037's tests only cover predicates inside the CTE body). The projection check has the same hole: `WITH n AS (SELECT body FROM notes) SELECT lower(body) FROM n` is not `ComputedColumn`, and `rows::check_for_stale_mapping` cannot catch it (field named `lower`) — plaintext of a mask-only column leaves under `reject` (the CTE twin of TASK-0187).

**Why it matters**: CTEs over protected tables are ordinary application SQL; the predicate silently matches nothing and the projection leak escapes both directions.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 scope_of carries the protected/read columns a CTE projects under the CTE name (and alias), and derived_scope handles SetExpr::Query/SetOperation bodies (union of both branches' carried columns)
- [ ] #2 Tests: WITH u AS (SELECT * FROM users) SELECT id FROM u WHERE email = 'a@b.io' is rewritten to the index prefix; WITH n AS (SELECT body FROM notes) SELECT lower(body) FROM n and the UNION derived-table form are refused under reject and warned under warn
<!-- AC:END -->
