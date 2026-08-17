---
id: TASK-0111
title: >-
  A cached prepared statement freezes its described positions, so protection
  added mid-session is not applied and stale-mapping is never re-checked
status: To Do
assignee:
  - TASK-0123
created_date: '2026-08-14 18:16'
updated_date: '2026-08-17 20:04'
labels:
  - security-review
  - security
  - read-path
dependencies: []
modified_files:
  - crates/proxy/src/rows.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/rows.rs:260-273` (`row_source`), `:310-343` (`check_for_stale_mapping`); positions captured at Describe in `portal.rs:313-321`.

**What**: `check_for_stale_mapping` runs only on `'T'` (RowDescription). A driver that describes a statement once and then executes it from cache produces DataRows with no preceding `'T'`, so `row_source` uses the `Positions` captured at Describe time and the stale-mapping heuristic never re-runs for that statement.

**Why it matters**: this is benign when a column merely moves OID (the captured transform still decrypts, since the envelope keys by key-id, not OID). But if a column's protection is *added* after the Describe — an operator config change or a `column_refresh_secs` re-resolution that captured empty positions — later cached Executes relay the now-protected column's stored bytes with no `'T'` to trigger a warn/refuse. It is silent under `warn`, and even under `reject` the only guard was the original Describe's `'T'`. The refresher's "picked up at the next RowDescription" model does not close this window for long-lived prepared statements. Depth on the CL-3 / task-0039 staleness area.

**Fix shape**: re-evaluate protected positions for a cached statement when the catalog generation changes (bump a catalog version on refresh and compare it against the version stamped on the portal's captured positions), or periodically invalidate cached Describe positions so a config/refresh change is reflected without a fresh `'T'`.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Cached-statement Executes re-check protected positions when the catalog generation has changed since Describe
- [ ] #2 A column whose protection is added mid-session is applied (or refused) on the next Execute of a cached statement
- [ ] #3 A test describes once, changes the catalog, and asserts the cached Execute no longer relays stored bytes
<!-- AC:END -->
