---
id: TASK-0200
title: >-
  ARCH-8: lib.rs carries a 160-line Error enum alongside the crate docs and
  module list
status: Triage
assignee: []
created_date: '2026-08-21 19:31'
labels:
  - code-review-rust
  - architecture
dependencies: []
modified_files:
  - crates/core/src/lib.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/core/src/lib.rs:144`

**What**: `lib.rs` is 285 lines, of which lines 140-299 are the `Error` enum (23 variants, several with struct payloads and feature gates). ARCH-8 keeps `lib.rs` to docs, `mod` declarations, re-exports and small central types, and moves error types out once they pass ~50 lines. The variants are shared by every module, which is the case the rule names for a dedicated `error.rs`. A `pub use error::Error;` keeps the public path `dbsec_core::Error` unchanged.

**Why it matters**: Maintainability only: the crate-level narrative (threat model, stored formats, features) and the error catalogue are both things a reader wants to read top to bottom, and each is currently interrupted by the other.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Error lives in crates/core/src/error.rs and is re-exported so dbsec_core::Error still resolves
- [ ] #2 lib.rs contains only crate docs, mod declarations, feature-gated re-exports and the derive re-export
- [ ] #3 Doc links ([`Error::…`]) across the crate still resolve under the workspace's deny(broken_intra_doc_links)
<!-- AC:END -->
