---
id: TASK-0129
title: >-
  MAX_PROTECTED_VALUE_LEN is a compile-time constant, so a deployment with
  larger protected values has no recourse
status: To Do
assignee:
  - TASK-0143
created_date: '2026-08-17 20:23'
updated_date: '2026-08-18 10:00'
labels:
  - code-review-rust
  - api
dependencies: []
modified_files:
  - crates/proxy/src/rows.rs
  - crates/proxy/src/config.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/rows.rs` (`MAX_PROTECTED_VALUE_LEN`)

**What**: the read path now refuses any protected column value over 16 MiB
(TASK-0107), because decrypting one costs several times its own size in
transient memory. The ceiling is a `const`. A deployment that encrypts a column
holding values above it — a document, an image, a large JSONB blob — gets its
sessions refused with `ProtectedValueTooLarge` and no way to raise the limit
short of rebuilding the binary.

**Why it matters**: 16 MiB is generous for field-level encryption, so this is
unlikely to bite, but the failure mode is a hard refusal on the read path
(ErrorResponse + session close) rather than a degraded one, and the operator's
only signal is an error naming a limit they cannot change. The config already
carries comparable knobs (`max_sessions`, `startup_timeout_secs`), so the
plumbing pattern exists.

**Fix shape**: a `max_protected_value_bytes` config field (default 16 MiB,
validated non-zero and below `MAX_MESSAGE_LEN`), carried on `RowContext`
alongside `on_unprotected` and read by `decrypt_row`.

**Origin**: discovered during TASK-0125 while fixing TASK-0107; that task's
description suggested "a configurable per-value ceiling" but did not require
one, and the wave kept the change to a constant.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The per-value read-path ceiling is settable from the config file, defaulting to the current 16 MiB
- [ ] #2 The value is validated at load time and rejected if zero or above the frame limit
- [ ] #3 A test asserts the configured ceiling is what decrypt_row enforces
<!-- AC:END -->
