---
id: TASK-0050
title: code-review-plan-wave1
status: To Do
assignee:
  - code-review-wave
created_date: '2026-08-11 22:41'
updated_date: '2026-08-11 22:41'
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
<!-- SECTION:NOTES:END -->
