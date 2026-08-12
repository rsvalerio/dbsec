---
id: TASK-0054
title: code-review-plan-wave5
status: Done
assignee:
  - code-review-wave
created_date: '2026-08-11 22:41'
updated_date: '2026-08-12 11:06'
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

Branch: code-review/TASK-0054

Landed on main as 8a759a8..139a804 (6 commits). All six members Done.
Pre-merge `ops verify` 7/7; integration `ops verify` failed once on
`-D unused-qualifications` for a fully-qualified `dbsec_core::envelope::Ciphers`
in the row tests (a lint that only fires against the rebased main), fixed and
re-verified 7/7. `cargo test --workspace --all-features` green either side.
Follow-up filed: TASK-0059 (Triage) for the Vault key source still flattening
its errors into `Error::KeySource(String)`.
<!-- SECTION:NOTES:END -->
