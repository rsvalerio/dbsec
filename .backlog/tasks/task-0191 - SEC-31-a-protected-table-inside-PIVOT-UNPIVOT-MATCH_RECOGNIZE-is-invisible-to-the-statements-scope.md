---
id: TASK-0191
title: >-
  SEC-31: a protected table inside PIVOT/UNPIVOT/MATCH_RECOGNIZE is invisible to
  the statement's scope
status: Triage
assignee: []
created_date: '2026-08-19 14:25'
labels:
  - code-review-rust
  - security
dependencies: []
modified_files:
  - crates/proxy/src/encrypt/query.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/encrypt/query.rs` (`QueryRewriter::scope_of`)

**What**: `scope_of` handles `TableFactor::Table`, `NestedJoin` and (since
TASK-0187) `Derived`, and lets everything else fall through `_ => {}`. That
silently includes the `PIVOT`, `UNPIVOT` and `MATCH_RECOGNIZE` wrappers, each of
which holds a `table` field that can name a protected relation.

A table inside one is therefore absent from the scope, so a predicate over its
protected column is neither rewritten into a blind-index match nor raised as an
`Unprotected` site — relayed verbatim even under `reject` — and the projection
check cannot see a computation over one of its mask-only columns either.

`Self::collect_copied_tables_from` already descends into all three, and the
comment there calls the asymmetry deliberate on the grounds that a missed table
"leaves a predicate unrewritten, which the client sees as an empty result". That
understates it: `=` matches nothing, but `<>` and `NOT IN` over an unrewritten
predicate match *every* row, and nothing is reported in either case.

**Mitigation, and why this is not urgent**: these are Oracle/Snowflake syntax.
`PostgreSqlDialect` parses them — verified, so the statement is *not* caught as
`Unprotected::Unparseable` — but a real PostgreSQL backend rejects them at
execution, so today the client gets a server-side syntax error and no data
moves. The gap is in the proxy's own defence in depth, and it becomes reachable
the moment the syntax is supported by whatever is behind the proxy.

**Origin**: raised by CodeRabbit on PR #17 and confirmed. Not a regression from
that branch; the arm predates it. TASK-0187 edited the comment on this match arm
and, by listing only the set-returning shapes, made it read as though nothing
else falls through.

**Fix**: recurse into the wrapped `table` of each of the three, exactly as
`collect_copied_tables_from` does, and correct the `_ => {}` comment.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A protected table wrapped in PIVOT, UNPIVOT or MATCH_RECOGNIZE is in the statement's scope, so a predicate over its protected column is rewritten or reported
- [ ] #2 A test drives each of the three wrappers and asserts the predicate is not relayed unreported under reject
<!-- AC:END -->
