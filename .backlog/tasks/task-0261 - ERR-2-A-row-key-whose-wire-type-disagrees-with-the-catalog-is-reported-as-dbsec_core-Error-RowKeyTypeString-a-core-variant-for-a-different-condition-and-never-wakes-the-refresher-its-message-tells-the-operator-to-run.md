---
id: TASK-0261
title: >-
  ERR-2: A row key whose wire type disagrees with the catalog is reported as
  dbsec_core::Error::RowKeyType(String), a core variant for a different
  condition, and never wakes the refresher its message tells the operator to run
status: Triage
assignee: []
created_date: '2026-08-22 00:38'
labels:
  - code-review-rust
  - error-handling
dependencies: []
modified_files:
  - crates/proxy/src/rows.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/rows.rs:872`

**What**: `RowKeyRef::TypeChanged` is a proxy-level, description-vs-resolution disagreement detected in `Resolved::row_key_ref` (rows.rs:291-298), but `decrypt_row` converts it into `Error::Wire(dbsec_core::Error::RowKeyType(format!("{table}.{column} came back as type oid {wire} but resolved as type oid {resolved}; re-resolve the proxy's columns, ...")))` (rows.rs:872-878) so that the existing `Error::Wire(RowKeyType(_))` arm of `is_refusal` (534) picks it up. `RowKeyType` is documented in core as 'the value cannot name a row' (NULL, bad UTF-8, wrong width — core/src/rowkey.rs:101-220); this is the only site in the workspace that fabricates one for a catalog-drift condition, and the proxy `Error` enum already has dedicated variants for every sibling refusal (`AmbiguousRowKey`, `AmbiguousRowInstance`, `StaleColumnMap`). The message instructs 're-resolve the proxy's columns', yet unlike the stale-mapping path (809, `request_refresh()`) nothing requests a re-resolution when `TypeChanged` is produced or refused, so the repair waits for the next timer tick.

**Why it matters**: Callers and tests cannot match on the condition (the TASK-0246 test has to grep the message for OIDs), the core error's documented meaning is diluted, and the refusal carries a remedy the proxy could have triggered itself.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A proxy `Error::RowKeyTypeChanged { table, column, wire, resolved }` variant with its own Display replaces the formatted `RowKeyType` string, and `is_refusal` lists it explicitly
- [ ] #2 Producing or refusing a `TypeChanged` description calls `RowContext::request_refresh()` so the re-resolution the message names happens immediately
- [ ] #3 The TypeChanged test matches the typed variant instead of substrings
<!-- AC:END -->
