---
id: TASK-0243
title: >-
  ERR-1: relay logs a transform or framing error at error! and then propagates
  it, so main logs the same failure again
status: Triage
assignee: []
created_date: '2026-08-21 19:54'
labels:
  - code-review-rust
  - error-handling
dependencies: []
modified_files:
  - crates/proxy/src/session.rs
  - crates/proxy/src/main.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/session.rs:642` (also 624-627, 647-650), `crates/proxy/src/main.rs:948`

**What**:
```rust
match transform(msg_type, &body).map_err(|e| {
    tracing::error!(direction, msg_type = %(msg_type as char), error = %e, "transform failed; closing session");
    e
})? {
```
Every `?` in the relay is preceded by a log-and-return closure, and the caller at `main.rs:948` logs the same error again (`tracing::warn!(%peer, error = %diag::chain(e), "session ended with error")`) at a different level and with the source chain the relay's `%e` drops.

**Why it matters**: one failure produces an ERROR line without the cause chain and a WARN line with it, on every refused session — noisy and contradictory for alerting. Log at the handling site only; the `direction`/`msg_type` context belongs on the error or in a span.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The relay propagates without logging, and direction/msg_type context is carried on the Error variant or a tracing::Span around the session
- [ ] #2 A log-capture test asserts a transform failure yields exactly one event
<!-- AC:END -->
