---
id: TASK-0009
title: >-
  SEC-33: the accept loop spawns an unbounded number of sessions, each able to
  buffer 1 GiB per direction
status: To Do
assignee:
  - TASK-0051
created_date: '2026-08-11 19:12'
updated_date: '2026-08-11 22:42'
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
- [ ] #1 A configurable max-concurrent-sessions limit gates the accept loop (semaphore or equivalent), with a documented default
- [ ] #2 Connections beyond the limit are refused or queued deliberately, and the outcome is logged with a rate limit rather than per connection
- [ ] #3 The per-session relay buffer has a documented ceiling, or is shrunk/reused so one large frame does not permanently reserve its size for the session
- [ ] #4 A test asserts the limit is enforced
<!-- AC:END -->
