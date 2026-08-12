---
id: TASK-0055
title: code-review-plan-wave6
status: To Do
assignee:
  - code-review-wave
created_date: '2026-08-11 22:41'
updated_date: '2026-08-11 22:42'
labels:
  - code-review-wave
dependencies:
  - TASK-0032
  - TASK-0033
modified_files:
  - crates/core/src/pgwire.rs
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
pgwire codec hardening: the two encoders narrow usize into fixed-width wire fields with unchecked casts, and the nullable length-prefixed value loop they share is copy-pasted in both directions. Same two functions, same fix.
<!-- SECTION:DESCRIPTION:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Overlaps: none
<!-- SECTION:NOTES:END -->
