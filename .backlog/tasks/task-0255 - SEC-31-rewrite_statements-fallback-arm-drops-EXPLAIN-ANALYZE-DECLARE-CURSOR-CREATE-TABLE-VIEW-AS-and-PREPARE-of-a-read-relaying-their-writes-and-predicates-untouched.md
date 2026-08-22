---
id: TASK-0255
title: >-
  SEC-31: rewrite_statement's fallback arm drops EXPLAIN ANALYZE, DECLARE
  CURSOR, CREATE TABLE/VIEW AS and PREPARE-of-a-read, relaying their writes and
  predicates untouched
status: Triage
assignee: []
created_date: '2026-08-21 19:55'
labels:
  - code-review-rust
  - security
dependencies: []
modified_files:
  - crates/proxy/src/encrypt/statement.rs
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/encrypt/statement.rs:144` (also :348)

**What**:
```rust
// statement.rs:136-145
match statement {
    Statement::Insert(insert) => ...,
    ...
    Statement::Prepare { statement, .. } => self.refuse_prepare(statement),
    _ => Ok(false),
}
// statement.rs:348
let Some(name) = write_target(statement) else { return Ok(false) };
```
sqlparser parses `EXPLAIN [ANALYZE] <stmt>` as `Statement::Explain { statement, analyze, .. }`, `DECLARE c CURSOR FOR <query>` as `Statement::Declare { stmts: [Declare { for_query: Some(..) }] }`, `CREATE TABLE ... AS <query>` / `CREATE [MATERIALIZED] VIEW ... AS <query>` with a `query` field, and `MERGE ... USING (<subquery>)`. None is dispatched: `EXPLAIN ANALYZE INSERT INTO users (email) VALUES ('x')` executes the insert with plaintext and no warning or refusal; `DECLARE c CURSOR FOR SELECT ... WHERE email = $1` (psycopg server-side cursors) matches nothing; `PREPARE p AS SELECT ... WHERE email = $1` passes `refuse_prepare` because `write_target` only recognises writes; MERGE's source subquery predicates are never walked.

**Why it matters**: `EXPLAIN ANALYZE` on a write is a plaintext write path that bypasses `reject` entirely; server-side cursors are a mainstream driver feature whose searchable predicates silently return nothing.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 rewrite_statement recurses into Explain.statement (rewriting when analyze, and treating a non-analyze EXPLAIN of a write as at least a warning), Declare[..].for_query, CreateTable.query, CreateView.query and Merge.source derived subqueries; Prepare of a read is rewritten or raised as a site
- [ ] #2 Tests under both policies for EXPLAIN ANALYZE INSERT ... VALUES ('a@b.io'), DECLARE c CURSOR FOR SELECT id FROM users WHERE email = 'a@b.io', CREATE TABLE t AS SELECT id FROM users WHERE email = 'a@b.io', PREPARE p AS SELECT id FROM users WHERE email = $1
<!-- AC:END -->
