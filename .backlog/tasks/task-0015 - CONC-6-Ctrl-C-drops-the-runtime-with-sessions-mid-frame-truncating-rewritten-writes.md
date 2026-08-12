---
id: TASK-0015
title: >-
  CONC-6: Ctrl-C drops the runtime with sessions mid-frame, truncating rewritten
  writes
status: Done
assignee:
  - TASK-0051
created_date: '2026-08-11 19:14'
updated_date: '2026-08-12 10:46'
labels:
  - code-review-rust
  - concurrency
  - main
dependencies: []
modified_files:
  - crates/proxy/src/main.rs
  - crates/proxy/src/session.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/main.rs:142-161`, `crates/proxy/src/main.rs:84`

**What**: Sessions are detached with `tokio::spawn` and never tracked. On Ctrl-C the select arm returns `Ok(())` immediately:

```rust
_ = tokio::signal::ctrl_c() => {
    tracing::info!("shutdown requested");
    return Ok(());
}
```

`serve` returns, `runtime.block_on` unwinds, and `main` drops the `Runtime` — which aborts every spawned task at its next await point without waiting for any of them. There is no `JoinSet`, no shutdown broadcast to sessions, and no drain deadline.

**Why it matters**: The relay writes a rewritten frame as two separate awaits — header, then body (`session.rs:170-171`) — and a sealed `Bind` or `Query` is a single logical write that has already been transformed. An abort between those two writes sends the upstream a header promising N bytes that never arrive: the backend sees a truncated message on a connection where the client believes its `INSERT` is in flight. The same window exists for a partially written `DataRow` reaching the client. Nothing about the shutdown is graceful — Ctrl-C in a container stop, a Kubernetes `SIGTERM` (which this does not even handle), or a systemd restart all take it.

Structured shutdown also fixes the observability gap: today the log says "shutdown requested" and the process exits, with no record of how many sessions were cut. A `JoinSet` plus a bounded drain (finish the current frame, refuse new connections, hard-abort after a deadline) makes the shutdown reportable and the truncation window closable.

Worth handling `SIGTERM` alongside `SIGINT` in the same change — a container runtime sends `SIGTERM`, which the current select arm does not observe at all, so the proxy is killed outright after the grace period.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Sessions are tracked (JoinSet or equivalent) and awaited on shutdown up to a bounded drain deadline
- [x] #2 A shutdown signal reaches sessions so a relay finishes the frame it is mid-write on before closing
- [x] #3 SIGTERM triggers the same path as SIGINT on unix
- [x] #4 Shutdown logs how many sessions drained and how many were aborted at the deadline
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Fixed in wave TASK-0051 (branch code-review/TASK-0051).

- AC #1: sessions are spawned into a `JoinSet` owned by `serve` instead of detached `tokio::spawn`s. `drain_sessions` awaits them for `SHUTDOWN_DRAIN_TIMEOUT` (10s) and then `JoinSet::shutdown()`s the remainder. The accept loop also reaps completed sessions with `join_next` so the set does not grow one entry per connection.
- AC #2: a `tokio::sync::watch<bool>` reaches every session (`session::ShutdownRx`). `relay` observes it in a `biased` `select!` *only* while waiting for the next frame header — never between the header write and the body write — so a rewritten frame is always finished before the relay closes. A dropped sender counts as shutdown too, which is what makes an early `serve` return also close sessions.
- AC #3: `shutdown_signal()` selects over SIGINT and, on unix, SIGTERM (`SignalKind::terminate()`), with a documented fallback to SIGINT-only if the SIGTERM handler cannot be installed.
- AC #4: `drain_sessions` returns and logs `(drained, aborted)` plus the deadline. `main::tests::drain_sessions_waits_then_aborts_at_the_deadline` asserts `(1, 1)` for one finished and one pending session, and `(0, 0)` for an empty set.
<!-- SECTION:NOTES:END -->
