---
id: TASK-0283
title: >-
  TEST-11: tests_e2e.rs asserts is_err() for malformed Describe/Close/Execute
  bodies and assert_ne!(plaintext) for a sealed Bind parameter, so the wrong
  error or a corrupt value passes
status: Triage
assignee: []
created_date: '2026-08-22 00:46'
labels:
  - code-review-rust
  - test
dependencies: []
modified_files:
  - crates/proxy/src/encrypt/tests_e2e.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/encrypt/tests_e2e.rs:373`

**What**: `malformed_describe_and_close_targets_fail_the_session` (crates/proxy/src/encrypt/tests_e2e.rs:373-380) asserts only `.is_err()` for each body, although `describe_target` (frame.rs:368-380) has a specific contract — `Error::Wire(dbsec_core::Error::Malformed)` for an unknown kind byte or empty body, and the `take_cstr` error for an unterminated name — so any other `Err` satisfies it. `a_fallback_array_does_not_drop_the_other_parameters_of_its_bind` (tests_e2e.rs:1159-1175) checks the sealed parameter only with `assert_ne!(bound.params[0].unwrap(), b"new@b.io")`, so a truncated, double-sealed or garbage value would pass; every sibling test in the file opens the stored bytes with `transform(...).open(...)` and compares to the plaintext (e.g. tests_e2e.rs:87, 106, 306).

**Why it matters**: The first test is the only coverage of the protocol-violation branch of `describe_target`; a regression that routed malformed bodies to a different error would go unnoticed. The second test exists to prove 'the sealed parameter must still be sealed' when a sibling array falls back; `assert_ne!` proves only that it changed, which is exactly the double-seal outcome `a_placeholder_reused_for_one_column_is_sealed_once_not_twice` guards against elsewhere.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 `malformed_describe_and_close_targets_fail_the_session` matches the specific error variant per body (`Error::Wire(dbsec_core::Error::Malformed)` for `b"X"` and `b""`, the cstr error for the unterminated names)
- [ ] #2 `a_fallback_array_does_not_drop_the_other_parameters_of_its_bind` decodes `bound.params[0]` as the binary-format sealed value and asserts `transform(true).open(..)` yields `b"new@b.io"`
<!-- AC:END -->
