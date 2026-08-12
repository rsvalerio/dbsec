---
id: TASK-0051
title: code-review-plan-wave2
status: To Do
assignee:
  - code-review-wave
created_date: '2026-08-11 22:41'
updated_date: '2026-08-11 22:41'
labels:
  - code-review-wave
dependencies:
  - TASK-0008
  - TASK-0009
  - TASK-0013
  - TASK-0015
  - TASK-0043
  - TASK-0046
modified_files:
  - crates/proxy/src/session.rs
  - crates/proxy/src/main.rs
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Session lifecycle and the relay loop: admission control, deadlines on the client-controlled startup phase, accept-error handling, graceful shutdown, and the frame-header construction the relay rewrites every frame with.
<!-- SECTION:DESCRIPTION:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Overlaps: TASK-0050 wave1 (session.rs, main.rs); TASK-0053 wave4, TASK-0056 wave7 (crates/proxy/src/main.rs)
<!-- SECTION:NOTES:END -->
