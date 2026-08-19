---
id: TASK-0170
title: >-
  TEST-11: the ErrorResponse truncation test does not pin the cap and never
  crosses a char boundary
status: To Do
assignee:
  - TASK-0181
created_date: '2026-08-19 08:32'
updated_date: '2026-08-19 09:01'
labels:
  - code-review-rust
  - test-quality
dependencies: []
modified_files:
  - crates/proxy/src/encrypt/unprotected.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/encrypt/unprotected.rs:354`

**What**: `error_response_is_a_well_formed_frame` ends with
`let long = error_response(&"x".repeat(4096)); assert!(long.len() < 4096);`.
`MAX_ERROR_MESSAGE` is 512, so the assertion has ~3.5 KiB of slack — raising the cap to 4000
keeps it green. Separately, the `while !message.is_char_boundary(end)` loop is the only
non-trivial logic in the function and is never exercised: the test's input is pure ASCII.

**Why it matters**: the cap exists because refusal messages embed client-chosen SQL identifiers
— attacker-influenced length — and it goes on the wire. The boundary loop exists because a
multi-byte identifier truncated mid-character would panic on the slice: a client-triggerable
panic in the refusal path. Neither property is defended by a test.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The truncation assertion pins the actual bound so raising the cap fails the test
- [ ] #2 A case truncates a message whose byte 512 falls inside a multi-byte character and asserts valid UTF-8 with no panic
<!-- AC:END -->
