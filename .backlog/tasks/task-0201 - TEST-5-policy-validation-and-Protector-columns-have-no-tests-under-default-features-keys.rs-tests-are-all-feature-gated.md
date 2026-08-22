---
id: TASK-0201
title: >-
  TEST-5: policy validation and Protector::columns have no tests under default
  features; keys.rs tests are all feature-gated
status: Triage
assignee: []
created_date: '2026-08-21 19:31'
labels:
  - code-review-rust
  - test-quality
dependencies: []
modified_files:
  - crates/core/src/policy.rs
  - crates/core/src/keys.rs
  - crates/core/src/protector.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/core/src/policy.rs:479` (also `crates/core/src/keys.rs:290`, `crates/core/src/protector.rs:127`)

**What**: The `policy.rs` test module is `#[cfg(all(test, feature = "keyfile"))]` because its fixtures are written as TOML, so `Policy::validate`, `validate_row_keys`, `build`, `row_keys` and `check_identifiers` — feature-independent logic that every front end relies on for its refusals — have zero tests in a `cargo test -p dbsec-core` with default features. `keys.rs` is gated the same way, which also hides the `Key` redacting-`Debug` tests and leaves `check_secret_file_mode` (used by the proxy and the vault crate) with no test anywhere in this crate. `Protector::columns()` has no test in the workspace. CI runs `--all-features`, so nothing is currently uncovered in CI — but the default-feature build is what a downstream `cargo test` sees, and the gating means a validation regression only surfaces when the keyfile feature happens to be on.

**Why it matters**: The policy refusals are the crate's "looks like protection but isn't" guard; tying their tests to an unrelated feature flag is a coverage cliff waiting for the first `default-features = false` consumer or CI matrix change.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 policy.rs validation/build tests run without the keyfile feature (fixtures built with ColumnPolicy::new/TablePolicy::new, TOML-shape tests kept under a narrower #[cfg(feature = "serde")] gate)
- [ ] #2 keys.rs Key Debug-redaction tests and a check_secret_file_mode test (0600 accepted, 0640/0644 refused with the path and 'holds' in the message, missing file tolerated) run under default features
- [ ] #3 Protector::columns has a test asserting the qualified names it yields
<!-- AC:END -->
