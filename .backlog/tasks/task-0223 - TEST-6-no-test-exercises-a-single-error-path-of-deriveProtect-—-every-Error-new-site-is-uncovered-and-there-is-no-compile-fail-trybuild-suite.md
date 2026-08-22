---
id: TASK-0223
title: >-
  TEST-6: no test exercises a single error path of #[derive(Protect)] — every
  Error::new site is uncovered and there is no compile-fail (trybuild) suite
status: Triage
assignee: []
created_date: '2026-08-21 19:49'
labels:
  - code-review-rust
  - tests
dependencies: []
modified_files:
  - crates/derive/src/lib.rs
  - crates/derive/Cargo.toml
  - crates/core/tests/derive.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/derive/src/lib.rs` (all 13 `Error::new` sites: lines 117, 120, 135, 142, 528, 537, 611, 623, 637, 667, 674, 681, 688); `crates/core/tests/derive.rs` (the only tests, all happy-path, gated on `derive,keyfile`)

**What**: The derive crate has no tests of its own (`crates/derive` contains only `Cargo.toml` and `src/lib.rs`; no `tests/`, no `#[cfg(test)]`). The ten integration tests in `crates/core/tests/derive.rs` cover seal/open round-trips and policy shape for two well-formed structs. Nothing compiles a rejected input: enum/tuple-struct targets, a struct with no `#[dbsec]` field, `row_key` naming a protected or absent field, a missing `table`, unknown keys at struct/field/mask level, wrong literal kinds (`table = 1`, `searchable = "yes"`, `mask_with = "*"`), an unsupported field type, or `Option<Option<String>>`. The crate's only usage example (`lib.rs:4-19`) is a ```` ```ignore ```` block, so it is never compiled either. There is no `trybuild` dev-dependency anywhere in the workspace.

**Why it matters**: TEST-6 / TEST-5. A derive's diagnostics *are* its API — the spans and messages are what the user sees — and they are the part most likely to regress silently when `expand` is restructured (FN-1 finding) or the attribute grammar grows. The sibling findings (ERR-11 panic on `row_key`, READ-5 validation gaps, shape_of `Vec<T>`) were all found by reading, not by a failing test, which is the symptom. Add `crates/derive/tests/ui.rs` with `trybuild::TestCases::compile_fail("tests/ui/*.rs")` (plus one `pass` case that is the README example), with `dbsec-core` as a dev-dependency; `.stderr` snapshots pin the span and message. Also consider turning the ```` ```ignore ```` doc example into a compiled doctest once the crate has a `dbsec-core` dev-dependency.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A trybuild (or equivalent) compile-fail suite exists under crates/derive/tests with one case per Error::new site
- [ ] #2 At least one pass case compiles the documented usage example
- [ ] #3 cargo test -p dbsec-derive runs the suite in CI
<!-- AC:END -->
