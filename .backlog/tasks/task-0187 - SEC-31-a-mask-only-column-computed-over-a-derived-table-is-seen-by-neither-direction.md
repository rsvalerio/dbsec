---
id: TASK-0187
title: >-
  SEC-31: a mask-only column computed over a derived table is seen by neither
  direction
status: Triage
assignee: []
created_date: '2026-08-19 10:15'
labels:
  - code-review-rust
  - security
dependencies: []
modified_files:
  - crates/proxy/src/encrypt/mod.rs
  - crates/proxy/src/encrypt/scope.rs
  - crates/proxy/src/rows.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/encrypt/mod.rs:1414` (`QueryRewriter::scope_of`), `crates/proxy/src/rows.rs:743` (`check_for_stale_mapping`)

**What**: `SELECT lower(body) FROM (SELECT body FROM notes) s` raises no
`Unprotected` site under either policy when `notes.body` is mask-only.

The write path cannot see it: `scope_of` only adds `TableFactor::Table` and
`TableFactor::NestedJoin` to a scope, so a derived table contributes no columns
and the outer `lower(body)` resolves against nothing. The inner `SELECT body
FROM notes` is a bare column reference and is correctly silent.

The read path cannot see it either: its backstop matches the *field name*
against `resolved.names`, and PostgreSQL names the output `lower`, not `body`.

**Why it matters**: identical in impact to TASK-0155 — a mask-only column is
stored as plaintext and the mask is the only thing that ever hides it, so the
statement hands the client the value the mask exists to withhold, silently, and
including under `on_unprotected = "reject"`. TASK-0155 closed the base-table
form of this by resolving the projection check against the catalog's read
direction; the derived-table form needs the subquery's output columns carried
into the enclosing scope, which is a larger change.

Note the same shape with a *cast* rather than a function call (`SELECT
body::text FROM (SELECT body FROM notes) s`) keeps the name and *is* caught by
the read-path backstop. The hole is specifically a function call over a derived
table.

**Origin**: discovered during TASK-0183 while fixing TASK-0155.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A derived table's output columns are resolvable in the enclosing scope, so a computation over a protected column projected out of one raises Unprotected::ComputedColumn
- [ ] #2 A test asserts SELECT lower(body) FROM (SELECT body FROM notes) s on a mask-only column is refused under reject and warned under warn
<!-- AC:END -->
