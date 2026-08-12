---
id: TASK-0054
title: code-review-plan-wave5
status: To Do
assignee:
  - code-review-wave
created_date: '2026-08-11 22:41'
updated_date: '2026-08-11 22:42'
labels:
  - code-review-wave
dependencies:
  - TASK-0025
  - TASK-0026
  - TASK-0028
  - TASK-0029
  - TASK-0030
  - TASK-0031
modified_files:
  - crates/core/src/envelope.rs
  - crates/core/src/keys.rs
  - crates/core/src/transform.rs
  - crates/core/src/mask.rs
  - crates/core/src/lib.rs
  - crates/core/tests/props.rs
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
dbsec-core crypto correctness and cost: AEAD nonce budget, how a stored value is interpreted versus how it was written, error typing through the crypto layer, per-value key-schedule rebuilds, and property/fuzz coverage for the modules that consume untrusted stored bytes.
<!-- SECTION:DESCRIPTION:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Overlaps: TASK-0053 wave4 (crates/core/src/keys.rs, crates/core/src/envelope.rs); TASK-0052 wave3 (crates/core/src/keys.rs)
<!-- SECTION:NOTES:END -->
