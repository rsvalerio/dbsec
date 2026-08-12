---
id: TASK-0015
title: >-
  CONC-6: Ctrl-C drops the runtime with sessions mid-frame, truncating rewritten
  writes
status: To Do
assignee:
  - TASK-0051
created_date: '2026-08-11 19:14'
updated_date: '2026-08-11 22:42'
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
- [ ] #1 Sessions are tracked (JoinSet or equivalent) and awaited on shutdown up to a bounded drain deadline
- [ ] #2 A shutdown signal reaches sessions so a relay finishes the frame it is mid-write on before closing
- [ ] #3 SIGTERM triggers the same path as SIGINT on unix
- [ ] #4 Shutdown logs how many sessions drained and how many were aborted at the deadline
<!-- AC:END -->
