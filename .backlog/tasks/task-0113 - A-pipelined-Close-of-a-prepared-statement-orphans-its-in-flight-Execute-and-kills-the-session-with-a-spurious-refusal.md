---
id: TASK-0113
title: >-
  A pipelined Close of a prepared statement orphans its in-flight Execute and
  kills the session with a spurious refusal
status: Done
assignee: []
created_date: '2026-08-14 16:48'
updated_date: '2026-08-14 21:42'
labels:
  - code-review-rust
  - idioms-correctness
dependencies: []
modified_files:
  - crates/proxy/src/portal.rs
  - crates/proxy/src/rows.rs
  - crates/proxy/src/encrypt.rs
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**Rule**: CL-3 (implicit assumption), SEC-31 adjacent (fail-closed applied to a healthy result set)

**File**: `crates/proxy/src/portal.rs:248` (`close_statement`), `crates/proxy/src/portal.rs:331` (`row_source`), `crates/proxy/src/encrypt.rs:319`, `crates/proxy/src/rows.rs:267`

**What**: `Pending::Execute(Some(name))` stores the *name* of the statement a portal was bound to, and `row_source()` resolves that name against `tracked.statements` only when the DataRow arrives. `close_statement` removes the entry immediately. In a pipelined batch the client sends everything before reading anything, so a driver that emits

```
Parse "s1" / Bind "p"→"s1" / Describe "p" / Execute "p" / Close S "s1" / Sync
```

has already had `close_statement(b"s1")` processed by the write path by the time the server's RowDescription and DataRows come back. `describe_answered` then finds no statement to attach positions to, `row_source()` returns `RowSource::Undescribed`, and `rows::inspect` raises `Error::UndescribedRow` — which `is_refusal` routes to `FrameAction::RefuseAndClose`: an ErrorResponse to the client and **the whole session torn down**, including any pipelined batch behind it.

Confirmed by driving `SessionPortals` through exactly that order; `row_source()` returns `Undescribed` even though the `Describe` was answered with two protected positions immediately before.

The existing test `closing_a_statement_forgets_it_and_its_portals` pins the *opposite* order (Close, then `expect_execute`), where the server would reject the Execute anyway, so it does not cover this.

The PostgreSQL JDBC driver emits `Close` for a statement it has decided not to cache in the same batch as its execution, so this is ordinary client traffic, not abuse.

**Why it matters**: a healthy result set is refused and a working connection is dropped, with an error message that says the proxy could not identify the row's columns. Under connection pooling every checkout that follows the same pattern dies the same way, so the proxy looks like an intermittent network fault. It fails closed rather than leaking, but it converts a supported client pattern into an outage.

**Suggested direction**: capture what the Execute needs at `expect_execute` time (the `Positions`, or an `Arc` to the `Statement` entry) rather than a name resolved later; or keep a closed statement alive until every `Pending` referencing it has been consumed.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 A pipelined Parse/Bind/Describe/Execute/Close S/Sync batch decrypts its DataRows with the positions the Describe returned, and does not refuse or close the session
- [x] #2 A portal Close pipelined ahead of its own Execute's results is covered by the same test
- [x] #3 A regression test in portal.rs drives close_statement between expect_execute and row_source and asserts RowSource::Portal
- [x] #4 Error::UndescribedRow is still raised for a genuine Execute of a statement the server never described
<!-- AC:END -->
