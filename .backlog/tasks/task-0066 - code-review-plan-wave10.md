---
id: TASK-0066
title: code-review-plan-wave10
status: Done
assignee:
  - code-review-wave
created_date: '2026-08-12 18:42'
updated_date: '2026-08-12 19:35'
labels:
  - code-review-wave
dependencies:
  - TASK-0062
  - TASK-0064
modified_files:
  - crates/proxy/src/encrypt.rs
  - crates/proxy/src/rows.rs
  - crates/proxy/src/session.rs
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Completing the fail-closed contract wave0 established: one place that refuses where it should rewrite (= ANY($1)), and one that refuses in the wrong shape (read path drops the connection instead of sending an ErrorResponse). Both hinge on the semantics of on_unprotected.
<!-- SECTION:DESCRIPTION:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Overlaps: TASK-0049 wave0 (crates/proxy/src/encrypt.rs) — wave0 is still In Progress with TASK-0037 open, and TASK-0062 is that finding's remainder. Landing this wave should close wave0.

Branch: code-review/TASK-0066

Landed: TASK-0062 and TASK-0064 both Done, merged fast-forward onto main (8ed2fd4, cfc76a9, d138171). Also touched crates/proxy/src/portal.rs (the new ParamAction variant) and crates/proxy/src/config.rs + README.md (docs), beyond the file scope triage recorded.
<!-- SECTION:NOTES:END -->
