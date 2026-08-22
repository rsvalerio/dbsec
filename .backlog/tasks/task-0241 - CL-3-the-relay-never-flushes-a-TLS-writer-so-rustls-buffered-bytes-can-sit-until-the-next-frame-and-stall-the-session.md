---
id: TASK-0241
title: >-
  CL-3: the relay never flushes a TLS writer, so rustls-buffered bytes can sit
  until the next frame and stall the session
status: Triage
assignee: []
created_date: '2026-08-21 19:54'
labels:
  - code-review-rust
  - concurrency
dependencies: []
modified_files:
  - crates/proxy/src/session.rs
  - crates/proxy/src/tls.rs
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/session.rs:656` (also 651-653, 668, 426)

**What**: Every forwarding arm does `write_all` and returns to the read loop without `flush()`:
```rust
let mut writer = forward.lock().await;
writer.write_all(&header).await?;
writer.write_all(&body).await?;
```
Same shape at 651-653 (`Replace`), 668 (`Reply`, `back.lock().await.write_all(&frames).await?`) and 426 (`upstream.write_all(&startup).await?`). Only `RefuseAndClose` (682) flushes. `Writers` wrap `MaybeTls`; tokio-rustls documents that `poll_write` writes into rustls's buffer and only opportunistically pushes to the socket — "when data channel is pending, some data may remain in rustls buffer. You must call `poll_flush`". Its `poll_write` breaks out of `write_io` on `Pending` and still reports the bytes as written.

**Why it matters**: with `[tls.downstream]` or `[tls.upstream]` configured, if the socket is not immediately writable when the last frame of a response (ReadyForQuery) or request (Sync) is written, the tail stays in rustls's buffer. The relay parks in `read_exact` on its reader and the writer is never polled again until another frame arrives in that direction — which, for a client waiting on ReadyForQuery or a backend waiting on Sync, never does. Sessions hang under ordinary backpressure, indistinguishable from idle. The plaintext path is unaffected, which is why the tests (plain `duplex`/`Vec` sinks) cannot see it.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Every FrameAction arm that writes (Relay, Replace, Reply) and the startup forward flush the writer before the relay returns to reading, or MaybeTls::poll_write guarantees the bytes reach the transport
- [ ] #2 A test relays through a tokio_rustls server/client pair over a small-capacity duplex and asserts the final frame is received without sending another frame
<!-- AC:END -->
