---
id: TASK-0065
title: code-review-plan-wave9
status: To Do
assignee:
  - code-review-wave
created_date: '2026-08-12 18:42'
updated_date: '2026-08-12 18:42'
labels:
  - code-review-wave
dependencies:
  - TASK-0059
  - TASK-0060
  - TASK-0061
modified_files:
  - crates/proxy/src/vault.rs
  - crates/core/src/lib.rs
  - crates/proxy/src/main.rs
  - plans/PLAN.md
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Vault key source follow-ups: the three threads wave3 and wave5 left behind — untyped error causes, expected-absence probes logged as ERROR, and migrated key material never cleaned up. All three live in vault.rs and share the same probe paths.
<!-- SECTION:DESCRIPTION:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Overlaps: none
<!-- SECTION:NOTES:END -->
