---
id: TASK-0163
title: 'SEC-15: unchecked as u32 narrowing in the DBS3 AAD length prefixes'
status: Done
assignee:
  - TASK-0178
created_date: '2026-08-19 08:31'
updated_date: '2026-08-19 09:40'
labels:
  - code-review-rust
  - security
dependencies: []
modified_files:
  - crates/core/src/envelope.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/core/src/envelope.rs:176`

**What**: `aad_with_row` writes `(column.len() as u32).to_be_bytes()` and
`(key.len() as u32).to_be_bytes()`. `usize`->`u32` wraps silently in release. The framing's
injectivity — the whole reason the length prefix exists — holds only while both lengths are
below 2^32; two row keys whose lengths differ by exactly 2^32 frame identically. Today
`pgwire::MAX_MESSAGE_LEN` makes this unreachable, but that bound lives in another crate, is
not asserted here, and the row key is not covered by `max_protected_value_bytes`.

**Why it matters**: a silent narrowing cast in the one function whose correctness decides
whether a relocated ciphertext is detected, guarded by an invariant that is nowhere stated or
checked.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 The prefixes use u64, or u32::try_from returning an error, so the framing cannot silently alias
- [x] #2 Round-trip compatibility with stored DBS3 values is preserved, or the change is versioned
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
aad_with_row now returns Result and builds each length prefix through u32::try_from, reporting the new Error::RowBindingFieldTooLong instead of wrapping. The u32 width and big-endian order are unchanged, so every stored DBS3 value still authenticates; a new test pins the exact AAD byte layout so the framing cannot be altered silently. The >4 GiB refusal path itself is not unit-tested — exercising it would need a 4 GiB allocation.
<!-- SECTION:NOTES:END -->
