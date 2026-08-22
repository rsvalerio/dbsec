---
id: TASK-0199
title: >-
  API-9: public config structs and enums in a published crate are exhaustive, so
  adding a field or variant is a breaking change
status: Triage
assignee: []
created_date: '2026-08-21 19:31'
labels:
  - code-review-rust
  - api
dependencies: []
modified_files:
  - crates/core/src/mask.rs
  - crates/core/src/policy.rs
  - crates/core/src/transform.rs
  - crates/core/src/rowkey.rs
  - crates/core/src/protector.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/core/src/mask.rs:651` (also `crates/core/src/policy.rs:57,77,167,219,243`, `crates/core/src/transform.rs:17`, `crates/core/src/rowkey.rs:473`, `crates/core/src/protector.rs:71`)

**What**: `dbsec-core` is published (docs.rs, semver policy stated in the crate docs, `Error` already `#[non_exhaustive]`), but the types an embedder is expected to construct or match are all exhaustive: `MaskSpec`, `ColumnPolicy`, `TablePolicy`, `Policy`, `RowKeyDecl`, `ProtectedColumn` (all-pub-field structs) and `TransformKind`, `WireForm`, `rowkey::Format`, `Opened` (enums). Adding a policy knob (the next `strict_*` flag, a mask option) or a stored form becomes a major version. `ColumnPolicy` / `TablePolicy` already have `new` + builder setters, so `#[non_exhaustive]` costs nothing there; `MaskSpec` has no constructor and no `Default`, so downstream code (including `dbsec-derive`'s generated `MaskSpec { … }` literal at `crates/derive/src/lib.rs:487`) can only build it by struct literal — it needs a `new`/`Default` before it can be closed.

**Why it matters**: The crate's stated stable surface is the stored format; the Rust API "follows semver in the usual way", and these types are the ones most likely to grow. Closing them now, pre-1.0, is free; after the first downstream `match` or literal it is a major bump.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 MaskSpec gains a constructor (and/or Default) so it can be built without a struct literal; dbsec-derive uses it
- [ ] #2 The public policy/mask structs and the TransformKind/WireForm/Format/Opened enums carry #[non_exhaustive] (or a per-type comment records why one is intentionally left open)
- [ ] #3 Workspace builds, tests and the derive macro's generated code compile under the change
<!-- AC:END -->
