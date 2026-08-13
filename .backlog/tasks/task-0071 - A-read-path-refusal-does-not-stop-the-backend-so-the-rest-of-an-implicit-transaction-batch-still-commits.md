---
id: TASK-0071
title: >-
  A read-path refusal does not stop the backend, so the rest of an
  implicit-transaction batch still commits
status: Done
assignee: []
created_date: '2026-08-13 20:19'
updated_date: '2026-08-13 21:29'
labels:
  - code-review-rust
  - correctness
  - security
  - read-path
dependencies: []
modified_files:
  - crates/proxy/src/rows.rs
  - crates/proxy/src/session.rs
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/rows.rs:237`

**What**: `refuse()` / `discard_until_ready()` only write toward the client —
`FrameAction::Substitute` goes to `forward`, which for the upstream->client relay is
`client_w` (`crates/proxy/src/session.rs:145`). Nothing is ever sent upstream, so the
backend is not put into an error state. The doc comment's claim that this is "the same
thing the backend itself does to a batch it has errored on" does not hold.

**Why it matters**: a client sends the simple query
`SELECT email FROM users; UPDATE accounts SET balance = 0;` (or the pipelined
Bind/Execute equivalent under one Sync). Under `on_unprotected = "reject"` the
RowDescription trips `StaleColumnMap`, so the proxy substitutes an ErrorResponse and
swallows frames up to ReadyForQuery. The backend never saw an error, so the UPDATE
executes and the implicit transaction commits. The relayed `Z` carries the backend's
real status (`I`), so the client sees ERROR + idle and concludes nothing was written.
The previous behaviour (dropping the connection) made the server abort the in-flight
implicit transaction, so this is a write-visibility regression, not a UX change.

**Origin**: /code-review high over 8ed2fd4^..d138171 (wave 10, TASK-0064). Mechanism
verified by hand against session.rs:145.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A refused batch cannot leave a committed write the client was told did not happen
- [ ] #2 The doc comment no longer claims parity with the backend's own error handling unless that parity is actually achieved
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Fixed in a3515d7. FrameAction::RefuseAndClose replaces Substitute: the client gets the 42501 ErrorResponse, both halves are shut down, and the backend rolls back the implicit transaction instead of committing behind the error. Verified by the full e2e driver matrix against dockerized Postgres (a_recreated_table_is_re_resolved_and_refused_in_strict_mode now asserts the session does NOT survive).
<!-- SECTION:NOTES:END -->
