---
id: TASK-0143
title: code-review-plan-wave26
status: Done
assignee:
  - code-review-wave
created_date: '2026-08-18 09:59'
updated_date: '2026-08-18 14:31'
labels:
  - code-review-wave
dependencies:
  - TASK-0128
  - TASK-0129
modified_files:
  - crates/proxy/src/session.rs
  - crates/core/src/pgwire.rs
  - crates/proxy/src/rows.rs
  - crates/proxy/src/config.rs
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Bounds on untrusted input: pre-auth limits and configurability
<!-- SECTION:DESCRIPTION:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Overlaps: TASK-0140 wave23 (crates/proxy/src/session.rs); TASK-0141 wave24 (crates/proxy/src/rows.rs)

Branch: code-review/TASK-0143
<!-- SECTION:NOTES:END -->
