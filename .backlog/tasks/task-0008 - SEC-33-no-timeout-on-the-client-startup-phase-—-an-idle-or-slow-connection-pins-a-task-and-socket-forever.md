---
id: TASK-0008
title: >-
  SEC-33: no timeout on the client startup phase — an idle or slow connection
  pins a task and socket forever
status: Done
assignee:
  - TASK-0051
created_date: '2026-08-11 19:12'
updated_date: '2026-08-12 10:45'
labels:
  - code-review-rust
  - security
  - session
dependencies: []
modified_files:
  - crates/proxy/src/session.rs
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/session.rs:35-61`

**What**: `CONNECT_TIMEOUT` (10s) covers exactly one operation — `TcpStream::connect` to the upstream (line 63). Everything the *client* controls before that has no deadline:

- `read_startup_message` (line 36) blocks in `read_exact` until the client sends bytes. A client that connects and sends nothing holds the task indefinitely.
- The same loop reads a length field and then `read_exact`s up to `MAX_MESSAGE_LEN` (1 GiB, `crates/core/src/pgwire.rs:23`) — a client can declare a large startup message and dribble it a byte at a time.
- `acceptor.accept(sock).await` (line 45) runs the whole TLS handshake with no timeout.
- After startup, `relay` (line 134) has no idle timeout on either direction.

**Why it matters**: This is textbook slowloris. Each held connection costs a tokio task, two file descriptors, and — once relaying starts — a `body` buffer that grows to the largest frame seen. Combined with the unbounded accept loop in `main.rs` (see the sibling finding), an unauthenticated attacker who can reach the listener exhausts file descriptors and memory without ever completing a startup message. The proxy sits in front of the database, so its exhaustion is a full outage for every legitimate client, and nothing in the process reclaims these connections — there is no idle reaper.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 The startup phase (first read through TLS handshake through the forwarded startup message) is wrapped in a single configurable deadline
- [x] #2 The downstream TLS handshake has its own timeout so a stalled handshake cannot pin the task
- [x] #3 An idle timeout applies to the relay loop, or the decision not to have one is documented with its rationale
- [x] #4 A test asserts that a client which connects and sends nothing is dropped within the deadline
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Fixed in wave TASK-0051 (branch code-review/TASK-0051).

- `session::run` wraps the whole client-driven prologue (`start_session`: first read → TLS handshake → upstream connect → forwarded startup message) in one `tokio::time::timeout` set from the new `startup_timeout_secs` config option (default 30s, validated non-zero). Timeout surfaces as `Error::StartupTimeout`.
- The downstream TLS handshake carries its own `TLS_HANDSHAKE_TIMEOUT` (10s) inside that deadline, surfacing as `Error::TlsHandshakeTimeout`.
- AC #3: the decision *not* to add a relay idle timeout is documented on `relay`'s doc comment — a pooled pgwire session is legitimately idle for hours and the relay cannot tell that from an abandoned socket, so the exhaustion risk is bounded at admission (`max_sessions`, TASK-0009) and by the startup deadline instead.
- AC #4: `session::tests::idle_client_is_dropped_at_the_startup_deadline` connects and sends nothing against a 100ms deadline and asserts `Error::StartupTimeout`.
<!-- SECTION:NOTES:END -->
