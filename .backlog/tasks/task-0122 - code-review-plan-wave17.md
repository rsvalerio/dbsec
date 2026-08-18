---
id: TASK-0122
title: code-review-plan-wave17
status: Done
assignee:
  - code-review-wave
created_date: '2026-08-17 20:02'
updated_date: '2026-08-18 09:43'
labels:
  - code-review-wave
dependencies:
  - TASK-0091
  - TASK-0100
  - TASK-0110
modified_files:
  - crates/proxy/src/encrypt.rs
  - crates/proxy/src/config.rs
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
PostgreSQL session-state and identifier assumptions the rewrite relies on
<!-- SECTION:DESCRIPTION:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Overlaps: TASK-0121 wave16, TASK-0123 wave18, TASK-0124 wave19 (crates/proxy/src/encrypt.rs); TASK-0119 wave14, TASK-0120 wave15 (crates/proxy/src/config.rs)

Branch: code-review/TASK-0122

Landed on main as aa3c94f, 8520b92, 4a61ada (fast-forward from code-review/TASK-0122). Rebase conflicts with wave 16/18 resolved by keeping both sides in encrypt.rs module docs, config.rs validation helpers and plans/PLAN.md. Integration verify caught one stale assertion from wave 16 (the_canonical_upsert_re_stores_the_value_it_just_sealed counted the old bare-hex literal prefix), fixed in 4a61ada. Follow-ups filed: TASK-0136 (standard_conforming_strings in the startup packet), TASK-0137 (double tokenization).
<!-- SECTION:NOTES:END -->
