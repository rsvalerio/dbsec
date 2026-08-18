---
id: TASK-0128
title: >-
  SEC-33: the relay buffers and SQL-parses 1 GiB frames before the backend has
  authenticated the client
status: To Do
assignee:
  - TASK-0143
created_date: '2026-08-17 20:23'
updated_date: '2026-08-18 10:00'
labels:
  - code-review-rust
  - security
dependencies: []
modified_files:
  - crates/proxy/src/session.rs
  - crates/core/src/pgwire.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/session.rs` (`relay`), `crates/core/src/pgwire.rs` (`frame_body_len`)

**What**: once the startup packet is forwarded, `relay` accepts any frame up to
`MAX_MESSAGE_LEN` (1 GiB) in either direction and hands the body to the query
rewriter for SQL parsing. Nothing in that path knows whether the backend has
finished authenticating the client: the AuthenticationOk / ErrorResponse the
backend sends is just another relayed frame. So a peer that completes a
startup handshake but never authenticates can still make the proxy resize its
relay buffer to 1 GiB and run the SQL parser over an arbitrary body, once per
frame, for as long as the connection lives.

PostgreSQL restricts pre-authentication message sizes for exactly this reason —
`PqRecvBuffer` growth is bounded until the client is authenticated.

**Why it matters**: TASK-0076 closed the startup-message half of this (a 16 KiB
`MAX_STARTUP_MESSAGE_LEN`), and TASK-0009 accepted the 1 GiB relay bound as
deliberate Postgres parity for *authenticated* traffic. The gap between them is
this window: frames after the startup packet and before AuthenticationOk are
authenticated-path bounds applied to an unauthenticated peer. `max_sessions`
(256) bounds the count but not the product.

**Fix shape**: track whether AuthenticationOk ('R' with code 0) has been seen
on the upstream->client direction, and apply a much smaller frame cap to the
client->upstream direction until it has. Possibly also skip the SQL rewriter
until then, since no statement is legal pre-auth.

**Origin**: discovered during TASK-0125 while fixing TASK-0076 — called out in
that task's description as "related, for the fix to consider but not
necessarily solve".
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Frames arriving from the client before AuthenticationOk has been relayed are bounded well below MAX_MESSAGE_LEN
- [ ] #2 A legitimate authenticated session still relays frames up to the 1 GiB Postgres parity limit
- [ ] #3 A test drives an oversized pre-authentication frame and asserts it is refused
<!-- AC:END -->
