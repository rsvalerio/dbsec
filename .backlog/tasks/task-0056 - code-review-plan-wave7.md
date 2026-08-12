---
id: TASK-0056
title: code-review-plan-wave7
status: Done
assignee:
  - code-review-wave
created_date: '2026-08-11 22:41'
updated_date: '2026-08-12 16:32'
labels:
  - code-review-wave
dependencies:
  - TASK-0014
  - TASK-0021
  - TASK-0023
  - TASK-0041
  - TASK-0042
  - TASK-0048
modified_files:
  - crates/proxy/src/tls.rs
  - crates/proxy/src/main.rs
  - crates/proxy/src/config.rs
  - crates/proxy/src/resolve.rs
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Startup path: TLS context construction and its untested error paths, the crypto-provider install, the config-to-keysource wiring that currently panics to restate an invariant, the control connection deadline and duplication, and the binary argument/exit behaviour no test covers.
<!-- SECTION:DESCRIPTION:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Overlaps: TASK-0053 wave4 (config.rs, main.rs, resolve.rs); TASK-0052 wave3 (resolve.rs, config.rs); TASK-0050 wave1 (resolve.rs, main.rs); TASK-0049 wave0 (config.rs); TASK-0051 wave2 (main.rs)

Branch: code-review/TASK-0056
<!-- SECTION:NOTES:END -->
