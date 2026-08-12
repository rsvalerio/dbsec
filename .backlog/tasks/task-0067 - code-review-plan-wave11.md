---
id: TASK-0067
title: code-review-plan-wave11
status: Done
assignee:
  - code-review-wave
created_date: '2026-08-12 18:42'
updated_date: '2026-08-12 19:12'
labels:
  - code-review-wave
dependencies:
  - TASK-0063
modified_files:
  - crates/proxy/src/config.rs
  - crates/proxy/src/tls.rs
  - crates/proxy/tests/common/mod.rs
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Completing the secret-file permission policy wave4 started: check_secret_file_mode covers keys_file and token_file but not the third secret in the config, the downstream TLS private key. Includes the reject-vs-warn design call a TLS key needs.
<!-- SECTION:DESCRIPTION:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Overlaps: TASK-0049 wave0 (crates/proxy/src/config.rs)

Branch: code-review/TASK-0067
<!-- SECTION:NOTES:END -->
