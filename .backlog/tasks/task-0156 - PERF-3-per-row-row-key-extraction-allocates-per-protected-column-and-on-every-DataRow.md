---
id: TASK-0156
title: >-
  PERF-3: per-row row-key extraction allocates per protected column and on every
  DataRow
status: Done
assignee:
  - TASK-0175
created_date: '2026-08-19 08:29'
updated_date: '2026-08-19 10:03'
labels:
  - code-review-rust
  - performance
dependencies: []
modified_files:
  - crates/proxy/src/rows.rs
  - crates/proxy/src/rowkey.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/rows.rs:742`

**What**: `decrypt_row` builds `Vec<Option<RowKey>>` unconditionally, one entry per protected
position. Every protected column of a table shares the same `RowKeySlot`, so a table with *k*
protected columns canonicalises the identical bytes *k* times per row; `canonical` allocates a
`String` that is then thrown away by `into_bytes()` into a second `Vec`. The `Vec` is allocated
for every DataRow even when the table declares no row key at all — a new per-row heap
allocation on the hot path of deployments that do not use the feature.

**Why it matters**: the read path is the hottest path in the proxy, and this function's own doc
is an argument about exactly this ("decrypting one value allocates several times over its own
size"). A `text` row key is bounded only by the 1 GiB frame cap — `max_protected_value_bytes`
caps protected values, not the key — so the multiplier is unbounded in size as well as count.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 The row key is canonicalised at most once per DataRow per distinct slot, and not at all when no position carries a slot
- [x] #2 canonical validates UTF-8 without the intermediate String on the pass-through arms
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Fixed in wave TASK-0175 (branch code-review/TASK-0175). `decrypt_row` now canonicalises the row key once per *distinct slot* per DataRow via the new `distinct_slots` helper, instead of once per protected column; the result is shared by every column that binds to it (`RowKeyOnce` splits the `Result` so the key is borrowed and the failure reason moved). A row whose positions carry no slot allocates nothing. `canonical` validates UTF-8 in place on the pass-through arms and no longer builds an intermediate `String`.
<!-- SECTION:NOTES:END -->
