---
id: TASK-0166
title: >-
  READ-8: a detected relocation is logged as a generic transform failure, with
  no column, table or row
status: Triage
assignee: []
created_date: '2026-08-19 08:31'
labels:
  - code-review-rust
  - observability
dependencies: []
modified_files:
  - crates/proxy/src/rows.rs
  - crates/proxy/src/session.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/rows.rs:766`

**What**: a `DBS3` value that fails to authenticate against its row returns `Error::Decrypt`,
which `is_refusal` excludes, so it reaches the relay loop and is logged as
`tracing::error!(direction, msg_type, error = %e, "transform failed; closing session")`. The
event carries the direction, the frame type, and "decryption failed (wrong key or tampered
data)" — no table, no column, no row key, no position. The identical line is emitted for a
key-rotation mishap or a stale column map.

**Why it matters**: detection whose alarm cannot be attributed is close to no detection. This
is the only externally visible product of row binding, and it does not say which cell fired.
Several other findings in this review additionally make this alarm fire on non-attacks, which
is how an operator learns to filter it.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The relocation case carries the qualified column name and the row key it failed against into the log event (both non-secret by the envelope docs)
- [ ] #2 The event is distinguishable in structured output from an unknown-key or stale-mapping failure
<!-- AC:END -->
