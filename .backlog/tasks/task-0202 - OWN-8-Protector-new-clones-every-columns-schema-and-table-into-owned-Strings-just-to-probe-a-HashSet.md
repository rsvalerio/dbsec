---
id: TASK-0202
title: >-
  OWN-8: Protector::new clones every column's schema and table into owned
  Strings just to probe a HashSet
status: Triage
assignee: []
created_date: '2026-08-21 19:31'
labels:
  - code-review-rust
  - ownership
dependencies: []
modified_files:
  - crates/core/src/protector.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/core/src/protector.rs:107` (also `crates/core/src/protector.rs:119`)

**What**: `row_bound` is a `HashSet<(String, String)>` built by `to_owned()`-ing each table's `(schema, table)`, and then each built column does `row_bound.contains(&(spec.schema.clone(), spec.table.clone()))` — two fresh allocations per column purely to form a lookup key of the right type. `policy` is borrowed for the whole of `new`, so the set can be `HashSet<(&str, &str)>` over `table.schema_and_table()` and the probe `row_bound.contains(&(spec.schema.as_str(), spec.table.as_str()))` with no allocation at all.

**Why it matters**: Construction-time only, so not a hot path — a readability/idiom finding. It is the one place in the crate where a clone exists to satisfy the type checker rather than to own data.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Protector::new builds the row-bound set and probes it with borrowed &str pairs; no String clone remains in the column wiring loop
- [ ] #2 Existing protector tests pass
<!-- AC:END -->
