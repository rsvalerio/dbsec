---
id: TASK-0053
title: code-review-plan-wave4
status: To Do
assignee:
  - code-review-wave
created_date: '2026-08-11 22:41'
updated_date: '2026-08-11 22:41'
labels:
  - code-review-wave
dependencies:
  - TASK-0010
  - TASK-0011
  - TASK-0019
  - TASK-0024
  - TASK-0027
  - TASK-0047
modified_files:
  - crates/proxy/src/config.rs
  - crates/proxy/src/vault.rs
  - crates/proxy/src/main.rs
  - crates/proxy/src/resolve.rs
  - crates/core/src/keys.rs
  - crates/core/src/envelope.rs
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Secret material policy, applied once across both crates: generate key material from the OS CSPRNG, redact credentials in Debug, zeroize key bytes on every path that holds them, and refuse or warn on world-readable secret files.
<!-- SECTION:DESCRIPTION:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Overlaps: TASK-0052 wave3 (vault.rs, resolve.rs, config.rs, crates/core/src/keys.rs); TASK-0056 wave7 (config.rs, main.rs, resolve.rs); TASK-0050 wave1 (main.rs, resolve.rs); TASK-0054 wave5 (crates/core/src/keys.rs, envelope.rs); TASK-0049 wave0 (config.rs); TASK-0051 wave2 (main.rs)
<!-- SECTION:NOTES:END -->
