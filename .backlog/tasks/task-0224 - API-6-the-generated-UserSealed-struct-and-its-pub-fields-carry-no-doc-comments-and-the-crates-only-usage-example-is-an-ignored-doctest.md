---
id: TASK-0224
title: >-
  API-6: the generated UserSealed struct and its pub fields carry no doc
  comments, and the crate's only usage example is an ignored doctest
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
**File**: `crates/derive/src/lib.rs:4-19` (```` ```ignore ```` example), `:155-160` and `:238-242` (sealed struct emission)

**What**: Two documentation gaps on the public surface the derive produces:

1. The sealed struct is emitted as `#vis struct #sealed_name { pub field: Ty, ... }` with no `#[doc]` on the struct or any field. `TABLE`, `policy`, `seal`, `open`, `open_lenient`, `masked` and every `*_term` fn *do* get `///` docs, so the sealed type is the one generated item that appears undocumented in a downstream crate's `cargo doc` and trips `#![deny(missing_docs)]` / `#![warn(missing_docs)]` in the user's crate, which they cannot fix without `#[allow]`ing the lint around a derive. A one-line `#[doc = "Stored form of [`User`]: every protected field as it is written to `public.users`."]` on the struct and `#[doc = "`column` in stored form (`Vec<u8>` envelope / FPE text / token)."]` per protected field costs nothing.

2. The crate-level example (the only one a `docs.rs` reader sees) is ```` ```ignore ````, rendered with the "This example is not tested" badge, and has in fact drifted from the code: it uses `sealed_derive(Debug, sqlx::FromRow)` but nothing in this crate or its docs says the derive is re-exported as `dbsec_core::Protect` only under the `derive` feature (`crates/core/src/lib.rs:102,121`). A proc-macro crate cannot compile a doctest against its own consumer, but the example can be moved to (or duplicated in) `dbsec_core::record` docs where it compiles under `#[cfg(feature = "derive")]`, or the derive crate can take `dbsec-core` as a dev-dependency so the block becomes a real doctest.

**Why it matters**: API-6 — doc tests with `///` are the contract; an `ignore`d example is the one kind that rots unnoticed, and undocumented generated pub items are a papercut every user with `missing_docs` hits on first use.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The generated sealed struct and its protected fields carry doc attributes; a downstream crate with #![deny(missing_docs)] compiles
- [ ] #2 The usage example is compiled somewhere (doctest in dbsec-core under the derive feature, or a trybuild pass case) and mentions the derive feature
<!-- AC:END -->
