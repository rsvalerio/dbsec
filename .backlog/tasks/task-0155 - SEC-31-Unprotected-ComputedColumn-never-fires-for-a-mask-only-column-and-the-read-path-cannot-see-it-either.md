---
id: TASK-0155
title: >-
  SEC-31: Unprotected::ComputedColumn never fires for a mask-only column, and
  the read path cannot see it either
status: To Do
assignee:
  - TASK-0183
created_date: '2026-08-19 08:29'
updated_date: '2026-08-19 09:01'
labels:
  - code-review-rust
  - security
dependencies: []
modified_files:
  - crates/proxy/src/encrypt/scope.rs
  - crates/proxy/src/encrypt/mod.rs
  - crates/proxy/src/encrypt/catalog.rs
  - crates/proxy/src/rows.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/encrypt/scope.rs:195`, call site `crates/proxy/src/encrypt/mod.rs:1093`

**What**: `computed_protected_column` resolves against the `TableScope` built from
`WriteCatalog::table`, and `WriteCatalog::new` skips every column with no transform — so
mask-only columns are absent from the scope and no `ComputedColumn` site is raised, despite
the function's own doc ("For a mask-only column that hands back the very value the mask exists
to hide").

The read-path backstop does not cover it either: `check_for_stale_mapping`'s computed branch
matches the *field name* against `resolved.names`, and PostgreSQL names the output of
`SELECT lower(email) FROM users` `lower`, not `email`. So that query on a mask-only column
reaches the client unmasked with no signal from either direction, including under `reject`.
A cast (`email::text`) keeps the name and *is* caught; an encrypted column *is* caught by the
write path. The hole is specifically mask-only behind a function call.

**Why it matters**: `WriteCatalog` grew a deliberate read-direction lookup
(`protects_reads`/`may_protect_reads`) precisely because the write-direction one is wrong for
mask-only columns — but the projection check still uses the write-direction scope.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The projection check resolves against a scope including mask-only columns, or ComputedColumn's doc states the limitation
- [ ] #2 A test asserts SELECT lower(m) FROM t on a mask-only column is refused under reject and warned under warn
<!-- AC:END -->
