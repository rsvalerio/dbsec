---
id: TASK-0014
title: >-
  ASYNC-6: the startup control connection has no timeout, so an unreachable
  database hangs the proxy forever
status: To Do
assignee:
  - TASK-0056
created_date: '2026-08-11 19:13'
updated_date: '2026-08-11 22:42'
labels:
  - code-review-rust
  - async
  - resolve
dependencies: []
modified_files:
  - crates/proxy/src/resolve.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/resolve.rs:19-92`

**What**: `resolve_columns` and its `connect` helper issue network work with no deadline anywhere:

- `tokio_postgres::connect(dsn, ...)` (lines 70 and 81) — no timeout, and the DSN's own `connect_timeout` parameter is only applied if an operator happens to put it in `control_dsn`.
- `client.query_opt(LOOKUP, ...)` (line 29) runs once per configured column, each without a timeout.

`serve` awaits `resolve_columns` before `TcpListener::bind` (`main.rs:123`, `main.rs:132`), so all of this happens before the proxy listens.

This is inconsistent with the data path, which does get a deadline: `session.rs:19` defines `CONNECT_TIMEOUT` and `session.rs:63` wraps the upstream connect in it. The control connection — the one that runs at startup, when a misconfigured or unreachable database is most likely — has none.

**Why it matters**: A host that accepts the TCP connection but never completes the Postgres handshake (a black-holing firewall, a database mid-failover, a wrong port pointing at some other listener) leaves the proxy hung with no listener, no log line past "startup", and no exit. Under a supervisor that health-checks the listen port it never becomes ready and never fails either, so it neither serves traffic nor gets restarted — it just sits there. A timeout turns that into a clear startup failure and a non-zero exit code, which `main.rs:84-89` is already set up to report.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The control-connection connect is wrapped in a timeout, reusing or generalizing session.rs's CONNECT_TIMEOUT rather than introducing a second unrelated constant
- [ ] #2 The per-column lookup query is bounded by a timeout as well
- [ ] #3 A timeout produces a distinct Error variant naming the control DSN host, and startup exits non-zero
- [ ] #4 A test covers a control endpoint that accepts TCP but never responds, asserting startup fails within the deadline
<!-- AC:END -->
