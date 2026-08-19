---
id: TASK-0156
title: >-
  PERF-3: per-row row-key extraction allocates per protected column and on every
  DataRow
status: Triage
assignee: []
created_date: '2026-08-19 08:29'
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
- [ ] #1 The row key is canonicalised at most once per DataRow per distinct slot, and not at all when no position carries a slot
- [ ] #2 canonical validates UTF-8 without the intermediate String on the pass-through arms
<!-- AC:END -->
