---
id: TASK-0134
title: >-
  A table protected only by a mask is invisible to the write catalog, so COPY
  over it is never an on_unprotected site
status: Done
assignee:
  - TASK-0139
created_date: '2026-08-17 20:58'
updated_date: '2026-08-18 10:34'
labels:
  - code-review-rust
  - security
dependencies: []
modified_files:
  - crates/proxy/src/encrypt.rs
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/encrypt.rs:156` (`WriteCatalog::new`), `crates/proxy/src/encrypt.rs:572` (the `Statement::Copy` arm)

**What**: `WriteCatalog::new` skips every column with no transform — "Mask-only columns have no transform; their writes pass through" — so a table whose only protection is a `mask` never enters `tables` or `bare_names`. `QueryRewriter::table` therefore returns `None` for it, and every refusal site keyed on that lookup declines to fire: `COPY t TO STDOUT`, `COPY (SELECT ... FROM t) TO STDOUT` (the query form added by TASK-0085), and the `Unsupported`/`NoColumnList` sites.

**Why it matters**: the mask-only case is the sharpest form of the COPY leak. An encrypted column at least leaves as ciphertext — fail-safe — but a mask-only column is stored as plaintext, and the mask applied on the read path is the *only* thing protecting it. `COPY masked_table TO STDOUT` and `COPY (SELECT masked FROM t) TO STDOUT` hand the client exactly the value the mask exists to hide, under `on_unprotected = "reject"` as much as under `warn`, with no warning anywhere. `rows.rs` already treats this case as the sharpest one (`a_computed_mask_only_column_is_reported`); the write-path classifier cannot see it at all.

**The design question**: the fix is not simply "put mask-only columns in the catalog". Most sites the lookup drives are about *writes*, and a plaintext write to a mask-only column is correct — flagging it would be a false refusal. What is needed is a separate notion of "this table has something the read path must cover", consulted by the read-direction sites (`COPY ... TO`, and any future one) while the write-direction sites keep using the transform-bearing catalog.

**Origin**: discovered during TASK-0123 while fixing TASK-0085.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 A table whose only protection is a mask is recognised by the read-direction refusal sites
- [x] #2 COPY t TO STDOUT and COPY (SELECT masked FROM t) TO STDOUT are refused under reject and warned about under warn when the only protection is a mask
- [x] #3 A plaintext write to a mask-only column is still not flagged, since it is the correct behaviour
- [x] #4 A test covers a mask-only table in both COPY forms and in both modes
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Fixed in wave TASK-0139 (branch code-review/TASK-0139). WriteCatalog now carries a read-direction table set (read_tables/read_bare_names) holding every configured column, not only the transform-bearing ones; QueryRewriter::reads_protected is its search_path-aware lookup. COPY ... TO (table form) and COPY (query) TO (via record_copied_table) consult it; COPY ... FROM STDIN and every write site keep using the transform catalog, so a plaintext write to a mask-only column is still not flagged. Copy site wording gained "or masked" since it now fires for tables with no encryption. Test: a_mask_only_table_is_a_copy_out_site_in_both_forms_and_both_modes.
<!-- SECTION:NOTES:END -->
