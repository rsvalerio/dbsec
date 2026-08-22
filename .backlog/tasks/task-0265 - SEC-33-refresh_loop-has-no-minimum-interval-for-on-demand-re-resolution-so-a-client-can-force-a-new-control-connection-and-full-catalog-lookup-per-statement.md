---
id: TASK-0265
title: >-
  SEC-33: refresh_loop has no minimum interval for on-demand re-resolution, so a
  client can force a new control connection and full catalog lookup per
  statement
status: Triage
assignee: []
created_date: '2026-08-22 00:38'
labels:
  - code-review-rust
  - security
dependencies: []
modified_files:
  - crates/proxy/src/resolve.rs
  - crates/proxy/src/rows.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/resolve.rs:78`

**What**: crates/proxy/src/resolve.rs:78-83 selects on `ctx.refresh_requested()` and, whenever it fires, runs `resolve_columns` (resolve.rs:124-229), which opens a fresh control connection (TCP + optional TLS + auth, resolve.rs:246-284) and re-runs the LOOKUP query for every `[[column]]` and `[[table]]`. The trigger at crates/proxy/src/rows.rs:803-809 calls `request_refresh()` on every RowDescription that carries a field with `table_oid != 0` named like a protected column but absent from the map — which under the default `on_unprotected = "warn"` is any `SELECT email FROM any_other_table` from any authenticated client, repeated as often as it likes. `Notify::notify_one` (rows.rs:457-459) only coalesces notifications that arrive while a refresh is in flight; as soon as one completes the next notification starts another. Nothing in `refresh_loop` or `Refresher` enforces a floor between on-demand resolutions, and the timer `interval` (default 300 s) is bypassed entirely by this path.

**Why it matters**: A single low-privilege client can turn the proxy into a connection-churn generator against the control database: one new backend connection and N catalog queries per statement it sends, indefinitely, consuming `max_connections`, authentication CPU and (with `[tls.upstream]`) a TLS handshake each time. It also keeps `RowContext::publish` swapping the shared map continuously. The comment at rows.rs:807-808 ('a false positive costs one catalog round-trip') is per statement, not per incident.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 `refresh_loop` enforces a minimum gap between on-demand re-resolutions (e.g. a `MIN_REFRESH_INTERVAL` constant or a config field), so notifications arriving inside the gap are coalesced into one resolution at its end instead of each starting a new control connection
- [ ] #2 A test drives `request_refresh()` many times in quick succession (paused tokio clock) and asserts `resolve_columns` — or a counting stand-in — runs once per gap, not once per request
- [ ] #3 The on-demand trigger's doc comment in rows.rs and the `Refresher` doc in resolve.rs state the floor, and README's description of column refresh mentions it
<!-- AC:END -->
