---
id: TASK-0052
title: code-review-plan-wave3
status: Done
assignee:
  - code-review-wave
created_date: '2026-08-11 22:41'
updated_date: '2026-08-12 16:15'
labels:
  - code-review-wave
dependencies:
  - TASK-0003
  - TASK-0006
  - TASK-0007
  - TASK-0016
  - TASK-0020
  - TASK-0040
modified_files:
  - crates/proxy/src/vault.rs
  - crates/proxy/src/resolve.rs
  - crates/proxy/src/config.rs
  - crates/core/src/keys.rs
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
VaultKeySource correctness: index-key integrity (silent re-mint, read-modify-write race), the missing rotation story for deterministic keys, the blocking bridge out of the sync KeySource trait, client timeouts, and the unit-test gap covering exactly these two modules.
<!-- SECTION:DESCRIPTION:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Overlaps: TASK-0053 wave4 (vault.rs, resolve.rs, config.rs, crates/core/src/keys.rs); TASK-0056 wave7 (resolve.rs, config.rs); TASK-0049 wave0 (config.rs); TASK-0050 wave1 (resolve.rs); TASK-0054 wave5 (crates/core/src/keys.rs)

Branch: code-review/TASK-0052
<!-- SECTION:NOTES:END -->
