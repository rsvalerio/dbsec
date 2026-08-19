---
id: TASK-0169
title: >-
  DUP-3: Unprotected::RowKeyMissing is constructed three times, differing only
  in shape
status: To Do
assignee:
  - TASK-0174
created_date: '2026-08-19 08:32'
updated_date: '2026-08-19 09:01'
labels:
  - code-review-rust
  - duplication
dependencies: []
modified_files:
  - crates/proxy/src/encrypt/mod.rs
  - crates/proxy/src/encrypt/seal.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/encrypt/seal.rs:140`

**What**: the same five-line initializer — `table: format!("{schema}.{table_name}")`,
`column: spec.name.clone()`, `shape: <literal>` — plus the same bail-out appears at
`encrypt/mod.rs:811`, `encrypt/seal.rs:140` and `encrypt/seal.rs:157`. Two of the three
re-derive `(schema, table_name)` from `resolved_name(...)` immediately above.

**Why it matters**: the sites are now split across two modules, so a change to how a row-bound
table is identified in the warning has to be made in two files. Low, because the three shapes
really are three different statements.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A single row_key_missing helper on QueryRewriter replaces all three sites
- [ ] #2 The three warning and refusal texts are byte-identical to today's
<!-- AC:END -->
