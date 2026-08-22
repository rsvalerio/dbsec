---
id: TASK-0260
title: >-
  PERF-3: decrypt_row rebuilds two HashSets and rescans positions on every
  DataRow to learn facts that are fixed by the RowDescription
status: Triage
assignee: []
created_date: '2026-08-22 00:38'
labels:
  - code-review-rust
  - performance
dependencies: []
modified_files:
  - crates/proxy/src/rows.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/rows.rs:888`

**What**: Per DataRow, `decrypt_row` (a) folds `positions` into two fresh `HashSet<&str>` to compute `repeated` (rows.rs:888-897) — two heap allocations per row for every protected result set, including the overwhelmingly common single-protected-column case where `repeated` is always empty; (b) rescans every position for `RowKeyRef::Ambiguous`/`TypeChanged` (861-881); and (c) materialises the row twice — `pgwire::parse_data_row` returns a `Vec<Option<&[u8]>>` which is immediately re-collected into a second `Vec<Option<Cow<[u8]>>>` (898-899). (a) and (b) depend only on `positions`, i.e. on the `Described` that `Described::new`/`rederived` already compute once per Describe (340-365), not on the row. The module's own doc for `distinct_slots` (1017-1029) and TASK-0156 (Done) set the standard that a deployment not using a feature 'pays nothing per DataRow' — the `repeated` fold was added by the TASK-0185 fix after that and breaks it.

**Why it matters**: This is the proxy's hottest path; two allocations and a hash-insert per protected column per row is pure overhead that scales with result-set size, and it is incurred even by deployments with no row key and no self-join. Moving it to description time removes the per-row cost and also lets `AmbiguousRowKey`/`TypeChanged` be refused once rather than re-evaluated per row.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 `Described` carries the per-position `repeated: bool` (or a precomputed set) computed in `Described::new` and `rederived`; `decrypt_row` no longer allocates a HashSet per row
- [ ] #2 The Ambiguous/TypeChanged refusal is decided from the `Described` (once per description, or via a precomputed `Option<Error>`-style field) rather than by scanning positions on every row
- [ ] #3 The DataRow is parsed into the `Cow` vector in one pass so a row allocates one values vector, not two
- [ ] #4 A test asserts that a single-protected-column row performs no per-row allocation beyond the values vector and the rewritten body
<!-- AC:END -->
