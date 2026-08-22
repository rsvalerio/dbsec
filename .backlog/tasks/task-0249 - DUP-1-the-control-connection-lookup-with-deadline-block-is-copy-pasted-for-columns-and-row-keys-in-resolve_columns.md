---
id: TASK-0249
title: >-
  DUP-1: the control-connection lookup-with-deadline block is copy-pasted for
  columns and row keys in resolve_columns
status: Triage
assignee: []
created_date: '2026-08-21 19:54'
labels:
  - code-review-rust
  - duplication
dependencies: []
modified_files:
  - crates/proxy/src/resolve.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/resolve.rs:137` and `crates/proxy/src/resolve.rs:174`

**What**: lines 137-150 and 174-187 are the same 14 lines — `timeout(deadline, client.query_opt(LOOKUP, &[schema, table, column]))`, the `ControlTimeout` map, the `Control` map and the `ColumnNotFound` `ok_or_else` — differing only in whether `column`/`decl` supplies the three names. `control_host(dsn.as_str())` also re-parses the DSN on every error construction in both copies and in `connect_with` (276-277).

**Why it matters**: a change to the deadline/error mapping (e.g. naming which column timed out) must be made twice, and the row-key copy already drifted once (it additionally reads `atttypid`, which the column copy discards).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 One async lookup helper (client, dsn, deadline, schema, table, column) -> Result<Row, Error> is used by both loops
- [ ] #2 resolve_columns stays <= 50 lines or the two loops become named helpers
<!-- AC:END -->
