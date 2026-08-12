---
id: TASK-0009
title: >-
  SEC-33: the accept loop spawns an unbounded number of sessions, each able to
  buffer 1 GiB per direction
status: Done
assignee:
  - TASK-0051
created_date: '2026-08-11 19:12'
updated_date: '2026-08-12 10:46'
labels:
  - code-review-rust
  - security
  - main
dependencies: []
modified_files:
  - crates/proxy/src/main.rs
  - crates/proxy/src/session.rs
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/main.rs:142-161`

**What**: The accept loop spawns one detached `tokio::spawn` per connection with no admission control:

```rust
accepted = listener.accept() => {
    let (socket, peer) = accepted?;
    let ctx = ctx.clone();
    tokio::spawn(async move { ... });
}
```

There is no semaphore, no max-connections config, and no tracking of live sessions. Each session's cost is not small: `session::run` opens a second TCP connection (and possibly a TLS session) to the upstream, and each of its two `relay` loops keeps a `body: Vec<u8>` that is `resize`d to the frame length — up to `MAX_MESSAGE_LEN`, 1 GiB (`crates/proxy/src/session.rs:160`, `crates/core/src/pgwire.rs:23`). That buffer is never shrunk for the life of the session.

**Why it matters**: Two separate exhaustion paths, both reachable pre-authentication because the proxy accepts and connects upstream before the client has authenticated to anything:

1. **Descriptor/connection exhaustion** — N client connections become 2N sockets plus N upstream backend connections. The upstream Postgres has a `max_connections` the proxy does not respect, so a burst through the proxy takes the database down for direct clients too.
2. **Memory exhaustion** — a handful of connections each sending one large frame reach multi-GiB resident size. Sixteen connections at 1 GiB is 16 GiB.

Combined with the missing startup timeouts ([[task-0008]]) the connections do not even have to do anything to be held. A proxy in front of the database is a single point of failure for every client behind it, so an unbounded accept loop is a direct availability risk rather than a tuning nicety.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 A configurable max-concurrent-sessions limit gates the accept loop (semaphore or equivalent), with a documented default
- [x] #2 Connections beyond the limit are refused or queued deliberately, and the outcome is logged with a rate limit rather than per connection
- [x] #3 The per-session relay buffer has a documented ceiling, or is shrunk/reused so one large frame does not permanently reserve its size for the session
- [x] #4 A test asserts the limit is enforced
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Fixed in wave TASK-0051 (branch code-review/TASK-0051).

- AC #1: new `max_sessions` config option (default 256, documented on the field, validated non-zero) drives an `Arc<Semaphore>` in the new `main::accept_loop`.
- AC #2: over-limit connections are refused deliberately (socket dropped, immediate close) rather than queued — rationale at the call site. Logging goes through `Refusals`, which emits at most one line per `REFUSAL_LOG_INTERVAL` (5s) carrying the count since the last line.
- AC #3: `relay` releases the per-direction body buffer back to `RELAY_BUFFER_RETAIN` (64 KiB) after any larger frame, so a one-off 1 GiB frame no longer reserves 1 GiB for the session's life.
- AC #4: `main::tests::accept_loop_refuses_connections_over_the_session_limit` runs the loop with `max_sessions = 1`, holds the permit with an admitted session and asserts the next connection is closed without becoming a session.

Also in this change: sessions are now a `JoinSet` (see TASK-0015) and the accept loop reaps finished sessions via `join_next`, so the tracked set does not grow one entry per connection ever served.
<!-- SECTION:NOTES:END -->
