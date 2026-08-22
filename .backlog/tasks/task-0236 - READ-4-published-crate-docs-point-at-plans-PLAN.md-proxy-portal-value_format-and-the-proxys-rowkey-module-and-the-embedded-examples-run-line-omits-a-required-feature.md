---
id: TASK-0236
title: >-
  READ-4: published crate docs point at plans/PLAN.md,
  proxy::portal::value_format and the proxy's rowkey module, and the embedded
  example's run line omits a required feature
status: Triage
assignee: []
created_date: '2026-08-21 19:50'
labels:
  - code-review-rust
  - readability
dependencies: []
modified_files:
  - crates/core/src/envelope.rs
  - crates/core/src/blind_index.rs
  - crates/core/src/transform.rs
  - crates/core/src/keys.rs
  - crates/core/src/mask.rs
  - crates/core/src/rowkey.rs
  - crates/core/examples/embedded.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/core/src/envelope.rs:41,49,60` (also `crates/core/src/blind_index.rs:4`, `crates/core/src/transform.rs:201`, `crates/core/src/keys.rs:82`, `crates/core/src/mask.rs:6`, `crates/core/src/rowkey.rs:63`, `crates/core/src/envelope.rs:221-222`, `crates/core/examples/embedded.rs:13`)

**What**: The same class of issue TASK-0206 files for the vault crate, in dbsec-core: seven doc comments defer the reasoning to `plans/PLAN.md`, a file that exists only in the repository and is not shipped with the crate, so on docs.rs the sentence "plans/PLAN.md carries the procedure" points nowhere. `rowkey.rs:63` cites `proxy::portal::value_format` and `envelope.rs:221` "the proxy's `rowkey` module" — internal symbols of a different crate, the second of which no longer exists since canonicalisation moved here (TASK-0192.01). `examples/embedded.rs:13` tells the reader to run `cargo run -p dbsec-core --features derive --example embedded`, but `Cargo.toml` declares `required-features = ["derive", "keyfile"]` for that example, so the documented command fails; the Makefile's `e2e` target passes `derive,keyfile`.

**Why it matters**: These are the reference paragraphs a library adopter reads to decide whether row binding, FPE or masking fits their threat model, and each one ends in a dangling pointer. Low severity, but the crate now advertises itself as a standalone library.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 No doc comment in crates/core/src references plans/PLAN.md or a proxy-internal symbol; each either inlines the relevant reasoning or links to a shipped location (README section, docs.rs page)
- [ ] #2 The run command in examples/embedded.rs matches the example's required-features
<!-- AC:END -->
