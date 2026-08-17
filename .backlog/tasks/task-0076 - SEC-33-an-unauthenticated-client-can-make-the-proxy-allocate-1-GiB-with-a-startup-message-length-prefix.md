---
id: TASK-0076
title: >-
  SEC-33: an unauthenticated client can make the proxy allocate 1 GiB with a
  startup-message length prefix
status: To Do
assignee:
  - TASK-0125
created_date: '2026-08-14 12:33'
updated_date: '2026-08-17 20:04'
labels:
  - code-review-rust
  - security
dependencies: []
modified_files:
  - crates/proxy/src/session.rs
  - crates/core/src/pgwire.rs
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/session.rs:286` (`read_startup_message`), `crates/core/src/pgwire.rs:50` (`startup_body_len`)

**What**: `read_startup_message` does `vec![0u8; 4 + body_len]` where `body_len` is taken
from the client's length prefix and validated by `startup_body_len` only against
`MAX_MESSAGE_LEN` — 1 GiB, the general frame limit. But PostgreSQL itself caps startup
packets at `MAX_STARTUP_PACKET_LENGTH` (10,000 bytes): a real startup message is a few
hundred bytes of parameters. The proxy therefore accepts, pre-authentication, an
allocation 100,000x larger than the server it fronts would. The `vec!` zeroes the pages,
so the RSS cost is real, and the startup loop reads multiple startup-phase messages per
connection.

**Why it matters**: this is the cheapest memory DoS the proxy offers. A client needs only
a TCP connect and 4 bytes to pin ~1 GiB for up to `startup_timeout_secs` (default 30 s).
`max_sessions` (default 256) bounds the count but not the product: 256 x 1 GiB is far past
OOM on any real host, and unlike the relay-path 1 GiB bound (TASK-0009, deliberate
Postgres parity for *authenticated* traffic), nothing legitimate needs a startup packet
over a few KiB.

Related, for the fix to consider but not necessarily solve: after the startup message is
forwarded, the relay buffers and SQL-parses up to 1 GiB frames from a client the backend
has not yet authenticated — PostgreSQL restricts pre-auth message sizes similarly.

**Fix shape**: a `MAX_STARTUP_MESSAGE_LEN` (e.g. 16 KiB) checked in `startup_body_len` or
at the `read_startup_message` call site, refusing oversized startup packets the way an
invalid length is refused today.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A startup message with a length prefix over the new cap is refused without the allocation being made
- [ ] #2 A legitimate startup message (including one with a large options parameter) still connects
- [ ] #3 A test drives the oversized-length case against read_startup_message or the binary
<!-- AC:END -->
