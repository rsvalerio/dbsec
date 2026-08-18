---
id: TASK-0098
title: >-
  A half-open session lingers after a read-path refusal or EOF, leaking the fd
  and any buffered frame
status: Done
assignee:
  - TASK-0124
created_date: '2026-08-14 14:06'
updated_date: '2026-08-17 20:51'
labels:
  - security-review
  - reliability
  - protocol
dependencies: []
modified_files:
  - crates/proxy/src/session.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/session.rs:421-440` and `:377-384`.

**What**: on a read-path refusal (or any upstream-initiated EOF) the relay shuts down only the *write* halves and returns `Ok`; `try_join!` does not cancel the sibling client->upstream relay, which is blocked in `read_exact(client_r)`. A client that holds its write half open keeps that task (and its fds, and any large buffered frame) alive until it closes or TCP times out. Verified by control-flow trace.

**Why it matters**: the security goal is still met — the ErrorResponse reaches the client and the backend rolls the batch back — so this is a resource-leak/DoS nuance, not a data leak. But combined with the pre-auth large-frame buffering it lets a client pin resources after a refusal.

**Fix shape**: cancel or time-bound the sibling relay half when one direction finishes on refusal/EOF.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 When one relay direction ends on refusal or EOF the sibling direction is cancelled or time-bounded
- [x] #2 A test asserts a refused session's tasks terminate without waiting on the client's write half
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Fixed in wave TASK-0124: session::join_relays replaces try_join!, ending the session when the first direction finishes and giving the other a bounded RELAY_DRAIN_TIMEOUT (5s) grace period instead of waiting on a client that never closes its write half. Grace period rather than immediate cancel so a half-closing client still receives the results in flight. Tests: a_refused_session_does_not_wait_on_the_clients_write_half, the_surviving_direction_finishes_inside_the_drain_window, the_first_directions_failure_is_the_sessions_error (paused-clock, via the new tokio test-util dev feature).
<!-- SECTION:NOTES:END -->
