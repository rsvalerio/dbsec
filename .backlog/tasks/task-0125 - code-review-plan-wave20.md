---
id: TASK-0125
title: code-review-plan-wave20
status: Done
assignee:
  - code-review-wave
created_date: '2026-08-17 20:02'
updated_date: '2026-08-17 20:25'
labels:
  - code-review-wave
dependencies:
  - TASK-0076
  - TASK-0107
modified_files:
  - crates/proxy/src/session.rs
  - crates/core/src/pgwire.rs
  - crates/proxy/src/rows.rs
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Resource bounds on untrusted input
<!-- SECTION:DESCRIPTION:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Overlaps: TASK-0123 wave18 (crates/proxy/src/rows.rs); TASK-0124 wave19, TASK-0126 wave21 (crates/proxy/src/session.rs)

Branch: code-review/TASK-0125
<!-- SECTION:NOTES:END -->
