---
id: TASK-0221
title: >-
  FN-1: expand is a 216-line function that validates input, declares the sealed
  struct, and emits seal/open/open_lenient/term/masked and two trait impls in
  one body
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
**File**: `crates/derive/src/lib.rs:113-329`

**What**: `expand` runs from input validation (struct kind, named fields, at-least-one-protected, row_key-is-plain) through nine independent `quote!` fragments (sealed decls, row expr, plain moves/clones, seal/open/lenient fields, policy columns/tables, `*_term` fns, `masked`) into a single 90-line `quote!` that lays out the sealed struct, an inherent impl with five items, a second inherent impl, and two trait impls. It is 216 lines at three abstraction levels — the `ProtectedField` methods below it already show the intended granularity (one method per generated expression).

**Why it matters**: FN-1 (≤50 lines, one abstraction level). The derive is the crate's only public surface and will grow (every new attribute touches this function); the first ~35 lines are a validation pass that belongs in a `fn validate(&DeriveInput, &[ProtectedField], &[(Ident, Type)]) -> Result<()>` next to `struct_attrs`, and the emission splits naturally into `sealed_struct()`, `record_impl()` (policy/seal/terms/masked), `sealed_impl()` (open/open_lenient) and `trait_impls()`, each returning `Tokens` from a small `Model { name, vis, table, sealed_name, plain, protected, row_key }`. That also makes the READ-5 derive-time checks (separate findings) land in one place.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 expand is ≤50 lines and delegates to named helpers per generated item
- [ ] #2 Input validation lives in one function separate from token emission
- [ ] #3 crates/core/tests/derive.rs still passes unchanged
<!-- AC:END -->
