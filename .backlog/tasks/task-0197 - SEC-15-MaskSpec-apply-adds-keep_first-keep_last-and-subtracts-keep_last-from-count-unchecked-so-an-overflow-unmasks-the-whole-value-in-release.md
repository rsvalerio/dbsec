---
id: TASK-0197
title: >-
  SEC-15: MaskSpec::apply adds keep_first + keep_last and subtracts keep_last
  from count unchecked, so an overflow unmasks the whole value in release
status: Triage
assignee: []
created_date: '2026-08-21 19:31'
labels:
  - code-review-rust
  - security
dependencies: []
modified_files:
  - crates/core/src/mask.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/core/src/mask.rs:676` (also `crates/core/src/mask.rs:682`)

**What**: `if count <= self.keep_first + self.keep_last` and `i >= count - self.keep_last` are plain `usize` arithmetic on operator-supplied config values. With `keep_first = usize::MAX, keep_last = 1` the sum wraps to 0, the full-mask branch is skipped, and `i < self.keep_first` is true for every position — every character is kept and the "mask" is the identity. In a debug build the same input panics on overflow. Both fields are `pub` and `MaskSpec` is built by struct literal (there is no constructor to validate in), and `Policy::validate` does not look inside the mask.

**Why it matters**: A mask is the read-path control for columns that stay plaintext at rest (`transform = "none"`), so a wrap here is a silent full disclosure rather than a crash. TOML cannot express values large enough to wrap through serde today (i64 range), so the reachable path is programmatic config, which is why this is Low — but `saturating_add` / `checked_sub` is the whole fix.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 MaskSpec::apply uses saturating/checked arithmetic so no combination of keep_first/keep_last can reveal more characters than intended
- [ ] #2 A test with keep_first = usize::MAX (and keep_last = usize::MAX) asserts the value is fully masked in both debug and release semantics
- [ ] #3 Optionally Policy::validate refuses a mask whose keep_first + keep_last cannot fit usize, with a message naming the column
<!-- AC:END -->
