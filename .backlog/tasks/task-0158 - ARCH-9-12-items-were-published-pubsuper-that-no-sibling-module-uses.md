---
id: TASK-0158
title: 'ARCH-9: 12 items were published pub(super) that no sibling module uses'
status: Triage
assignee: []
created_date: '2026-08-19 08:30'
labels:
  - code-review-rust
  - architecture
dependencies: []
modified_files:
  - crates/proxy/src/encrypt/array.rs
  - crates/proxy/src/encrypt/scope.rs
  - crates/proxy/src/encrypt/seal.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/encrypt/scope.rs:44`

**What**: the split widened items wholesale rather than per-consumer. These 12 have no
reference anywhere in `crates/proxy/src/encrypt/` outside their own file — verified by dropping
`pub(super)` from all 12 in a scratch clone and confirming `cargo check --all-targets` exits 0:

`array.rs`: `BoundArray`, `decode_binary_array`, `decode_text_array`, `encode_binary_array`,
`encode_text_array`. `scope.rs`: `ColumnResolution`, `resolve_column`, `expr_operands`,
`protected_reference`, `predicate_operands`. `seal.rs`: `row_key_source`,
`seal_tuple_assignment`.

**Why it matters**: the stated point of the split was to shrink what a reviewer holds at once,
and a `pub(super)` item is one a reviewer of *any* file in `encrypt/` must consider reachable.
`decode_text_array` parses client-chosen bytes and returns `Option`; its `None` contract is
enforced only by `array_parameter`, so publishing the raw decoder invites a future caller that
skips the gate. `ColumnResolution::Ambiguous` is the same shape — `column_ref` is meant to be
the only way out.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 All 12 items are module-private; cargo check --all-targets and clippy stay clean
- [ ] #2 Each module's remaining pub(super) set is its documented interface only
<!-- AC:END -->
