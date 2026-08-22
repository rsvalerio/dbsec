---
id: TASK-0245
title: >-
  ERR-11: an FPE value with fewer than six digits kills the session instead of
  refusing the statement
status: Triage
assignee: []
created_date: '2026-08-21 19:54'
labels:
  - code-review-rust
  - error-handling
dependencies: []
modified_files:
  - crates/proxy/src/encrypt/frame.rs
  - crates/proxy/src/encrypt/seal.rs
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/encrypt/frame.rs:266`, `crates/proxy/src/encrypt/seal.rs:590`

**What**: `FpeTransform::seal` returns `Error::FpeDomain` for any plaintext with fewer than `MIN_FPE_DIGITS` (6) digits (`crates/core/src/transform.rs:270`) — e.g. `INSERT INTO t (phone) VALUES ('n/a')` or a Bind parameter `"12345"`. Both call sites propagate with `?`:
```rust
encode_param(transform.seal(value, key.as_ref())?, transform.wire(), binary)           // frame.rs:266
let sealed = transform.seal(&plaintext, row_key.as_ref()).map_err(Error::Wire)?;     // seal.rs:590
```
`bind()` returns `Result<FrameAction, Error>` and `seal_expr` converts via `From<Error> for Rejection` into `Rejection::Fatal`; the relay logs "transform failed; closing session" (`session.rs:643`) and drops the socket with no ErrorResponse. This is ordinary well-formed client data, the same shape TASK-0149 fixed for row keys and `record_param` fixed for conflicting placeholders.

**Why it matters**: under a connection pool the client retries and kills the next connection too; the client sees `Closed` rather than a `DbError` naming the column; on the simple-protocol path transaction state is lost silently.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 FpeDomain from seal at Bind time and in seal_expr becomes a statement-level Rejection::Refused with an ErrorResponse naming the column and the six-digit minimum; the session stays open
- [ ] #2 A test in tests_e2e.rs writes a 5-digit value to an FPE column and asserts the client receives an ErrorResponse and the next statement on the same connection succeeds
<!-- AC:END -->
