---
id: TASK-0049
title: code-review-plan-wave0
status: To Do
assignee:
  - code-review-wave
created_date: '2026-08-11 22:41'
updated_date: '2026-08-11 22:41'
labels:
  - code-review-wave
dependencies:
  - TASK-0001
  - TASK-0002
  - TASK-0017
  - TASK-0018
  - TASK-0036
  - TASK-0037
  - TASK-0045
modified_files:
  - crates/proxy/src/encrypt.rs
  - crates/proxy/src/config.rs
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Write path fail-open coverage: every site where a write to a protected column is silently or near-silently left in plaintext, plus the strict/fail-closed switch they all need and the SQL-text fidelity of the rewrite that carries them.
<!-- SECTION:DESCRIPTION:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Overlaps: TASK-0050 wave1 (crates/proxy/src/encrypt.rs); TASK-0052 wave3, TASK-0053 wave4, TASK-0056 wave7 (crates/proxy/src/config.rs)
<!-- SECTION:NOTES:END -->
