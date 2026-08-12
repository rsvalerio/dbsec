---
id: TASK-0050
title: code-review-plan-wave1
status: Done
assignee:
  - code-review-wave
created_date: '2026-08-11 22:41'
updated_date: '2026-08-12 17:00'
labels:
  - code-review-wave
dependencies:
  - TASK-0012
  - TASK-0035
  - TASK-0038
  - TASK-0039
  - TASK-0044
modified_files:
  - crates/proxy/src/encrypt.rs
  - crates/proxy/src/rows.rs
  - crates/proxy/src/session.rs
  - crates/proxy/src/resolve.rs
  - crates/proxy/src/main.rs
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Extended-protocol state: how per-session prepared-statement and portal state is kept, bounded, and kept in agreement between the write path (Parse/Bind) and the read path (RowDescription/DataRow). These restructure the same state and must land together.
<!-- SECTION:DESCRIPTION:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Overlaps: TASK-0049 wave0 (crates/proxy/src/encrypt.rs); TASK-0051 wave2 (session.rs, main.rs); TASK-0052 wave3 (resolve.rs); TASK-0053 wave4 (main.rs, resolve.rs); TASK-0056 wave7 (resolve.rs, main.rs)

Branch: code-review/TASK-0050

Landed on main as 0011874..4b72b61. All five members Done.

Rebased twice: once from the original branch point (19dd4c6) onto wave0/2/3/5/6, and again onto wave4/wave7 before merging. Conflicts were in encrypt.rs (wave0's FrameAction/Unprotected/Rejection restructuring), rows.rs (wave6's Result-returning encode_data_row), session.rs, main.rs (wave4's ValidatedConfig/KeySourceConfig) and resolve.rs (wave7's Dsn type and per-step deadline). Every conflict was resolved by re-applying this wave's change onto the other wave's shape, never by discarding it.

Two problems surfaced only under `make e2e` and are fixed here:
- Wave0 answers a refused statement itself, so the backend never sees it and owes no response. Expectations are now recorded only for frames actually forwarded upstream.
- PostgreSQL ignores Flush/Sync in copy-in mode, so a driver's pipelined Sync left a batch marker no ReadyForQuery ever answered — every later response was then attributed one expectation early, which surfaced as `UndescribedRow` on the next ordinary query. `SessionPortals::copy_data` drops exactly those markers.

Pre-merge `ops verify` 7/7; integration `ops verify` 7/7; `cargo test --all --all-features` 126 proxy + 6 cli + 37 core + 15 props passing; `make e2e` green across tokio-postgres, sqlx and psycopg.
<!-- SECTION:NOTES:END -->
