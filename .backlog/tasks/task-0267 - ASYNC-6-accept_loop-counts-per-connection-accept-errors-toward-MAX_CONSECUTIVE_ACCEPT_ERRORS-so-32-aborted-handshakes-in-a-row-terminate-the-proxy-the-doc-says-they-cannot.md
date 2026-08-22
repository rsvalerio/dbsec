---
id: TASK-0267
title: >-
  ASYNC-6: accept_loop counts per-connection accept errors toward
  MAX_CONSECUTIVE_ACCEPT_ERRORS, so 32 aborted handshakes in a row terminate the
  proxy the doc says they cannot
status: Triage
assignee: []
created_date: '2026-08-22 00:38'
labels:
  - code-review-rust
  - async
dependencies: []
modified_files:
  - crates/proxy/src/main.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/main.rs:894`

**What**: crates/proxy/src/main.rs:894-905: every non-fatal `accept()` error does `consecutive_errors += 1` and returns `Err` once the counter reaches `MAX_CONSECUTIVE_ACCEPT_ERRORS` (32, main.rs:53). `is_per_connection_accept_error` (main.rs:822-830) is consulted only to skip the backoff sleep, not to exempt the error from the counter. The doc on `is_fatal_accept_error` (main.rs:805-812) says ECONNABORTED/ECONNRESET 'say nothing about the listening socket ... Those shed one connection and the loop continues; killing the process would drop every healthy session', and the ceiling is described as catching 'a listener failing in a way this predicate cannot name' — but a run of 32 peer-aborted connections with no successful accept in between (a scanner or a misbehaving load balancer health check under `TCP_DEFER_ACCEPT`/syncookies) trips it.

**Why it matters**: A remote, unauthenticated party that can produce consecutive ECONNABORTED results can end the process and every healthy session with it — exactly the outcome the classification was written to prevent. The counter only resets on a successful accept, so a quiet period with only aborted attempts is enough.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Per-connection accept errors (as classified by `is_per_connection_accept_error`) do not increment `consecutive_errors`; only unclassified/transient-resource errors do
- [ ] #2 A test feeds 32+ consecutive `ConnectionAborted` errors and asserts the loop keeps accepting
- [ ] #3 The doc on `MAX_CONSECUTIVE_ACCEPT_ERRORS` / `is_fatal_accept_error` matches the implemented rule
<!-- AC:END -->
