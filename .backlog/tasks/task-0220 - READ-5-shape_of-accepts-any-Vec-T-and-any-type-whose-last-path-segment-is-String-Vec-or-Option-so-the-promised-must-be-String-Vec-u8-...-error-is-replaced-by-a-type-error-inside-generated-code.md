---
id: TASK-0220
title: >-
  READ-5: shape_of accepts any Vec<T> and any type whose last path segment is
  String, Vec or Option, so the promised 'must be String, Vec<u8>, ...' error is
  replaced by a type error inside generated code
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
**File**: `crates/derive/src/lib.rs:635-662`

**What**: `shape_of` classifies by the last path segment only and never inspects `Vec`'s generic argument. `Vec<String>`, `Vec<i64>`, `Vec<Vec<u8>>`, `Option<Vec<String>>`, `bytes::Bytes`-style aliases named `String`, or a user type `mod m { struct Vec; }` all pass as `Repr::Bytes`/`Repr::Text`. The failure then surfaces as a type error in the expansion — e.g. `expected &[u8], found &Vec<String>` on `::core::convert::AsRef::<[u8]>::as_ref(__value)` — pointing at macro-generated tokens with the `#[dbsec]` span lost, instead of the single clear message the `err` closure already carries. `Option<Option<_>>` is refused but `Option<Vec<String>>` is not, which is inconsistent.

**Why it matters**: The doc comment on the function acknowledges "judged by the type's last path segment, which is what a derive can see", which is the right limit for *aliases* (a derive cannot resolve `type Bytes = Vec<u8>`). But the generic argument of `Vec` is right there in the AST; checking that it is a single `u8` path segment keeps the promised diagnostic for the most likely mistake (`Vec<String>` for a multi-valued field). A user who wants an alias can still name it `Vec`/`String` as documented.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A #[dbsec] field of type Vec<T> with T not u8 (at any Option nesting) yields the shape_of error at the field's type span
- [ ] #2 A compile-fail test covers Vec<String> and Option<Vec<i64>>
<!-- AC:END -->
