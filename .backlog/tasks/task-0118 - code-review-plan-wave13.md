---
id: TASK-0118
title: code-review-plan-wave13
status: To Do
assignee:
  - code-review-wave
created_date: '2026-08-17 20:02'
updated_date: '2026-08-17 20:03'
labels:
  - code-review-wave
dependencies:
  - TASK-0082
  - TASK-0093
  - TASK-0094
  - TASK-0095
  - TASK-0097
  - TASK-0101
modified_files:
  - crates/core/src/envelope.rs
  - crates/core/src/keys.rs
  - crates/core/src/transform.rs
  - crates/proxy/src/columns.rs
  - crates/proxy/src/vault.rs
  - Cargo.toml
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Crypto core: envelope binding, nonce safety, and key-material hygiene
<!-- SECTION:DESCRIPTION:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Overlaps: TASK-0119 wave14 (crates/proxy/src/vault.rs); TASK-0126 wave21 (crates/core/src/envelope.rs, crates/proxy/src/vault.rs)
<!-- SECTION:NOTES:END -->
