---
id: TASK-0219
title: >-
  READ-5: repeated or conflicting #[dbsec] keys silently take the last value —
  fpe and token on one field, two table = or column = entries, searchable set
  twice
status: Triage
assignee: []
created_date: '2026-08-21 19:49'
labels:
  - code-review-rust
  - structure
dependencies: []
modified_files:
  - crates/derive/src/lib.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/derive/src/lib.rs:511-535` (struct_attrs), `:564-599` (field_attrs), `:608-628` (MaskArgs::parse)

**What**: All three attribute parsers fold metas into mutable locals with plain assignment, so repetition and contradiction are accepted and the last spelling wins without a diagnostic:

- `#[dbsec(fpe, token)]` / `#[dbsec(encrypt)] #[dbsec(none)]` on one field → `Kind::Token` / `Kind::None`, the earlier kind discarded
- `#[dbsec(searchable, searchable = false)]` → not searchable
- `#[dbsec(mask, mask(keep_last = 4))]` → second mask; `mask(keep_last = 4, keep_last = 2)` → 2
- `#[dbsec(table = "a", table = "b")]` or two `#[dbsec(table = ..)]` attributes → `"b"`; same for `row_key` and `column`
- a bare `#[dbsec]` next to `#[dbsec(fpe)]` is `continue`d, so "bare means encrypt" is only true when it is the only attribute

**Why it matters**: READ-5 — the derive is the policy declaration; a contradictory declaration that compiles to one of its halves is exactly the "looks like protection while providing a different one" failure `Policy::validate` exists to prevent. `fpe, token` in particular changes the stored form (and what `open` will accept) with no signal. Track whether each key was already set (an `Option` per key, or a `seen: HashSet<&str>`) and return `Error::new(meta.span(), "duplicate / conflicting `..`")`; for the kind, keep an `Option<Kind>` and refuse a second transform word.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A second transform word, a repeated table/row_key/column/searchable/detokenize/mask key, or a repeated mask sub-key is a spanned compile error
- [ ] #2 Compile-fail tests cover the conflicting-transform and repeated-table cases
<!-- AC:END -->
