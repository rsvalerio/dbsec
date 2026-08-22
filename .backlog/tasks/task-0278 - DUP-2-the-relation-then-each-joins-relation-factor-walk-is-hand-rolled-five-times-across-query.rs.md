---
id: TASK-0278
title: >-
  DUP-2: the 'relation then each join's relation' factor walk is hand-rolled
  five times across query.rs
status: Triage
assignee: []
created_date: '2026-08-22 00:45'
labels:
  - code-review-rust
  - duplication
dependencies: []
modified_files:
  - crates/proxy/src/encrypt/query.rs
  - crates/proxy/src/encrypt/statement.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/encrypt/query.rs:139`

**What**: `std::iter::once(&table.relation).chain(table.joins.iter().map(|join| &join.relation))` (or its `_mut` twin) is written out in rewrite_derived_tables (query.rs:139-141), scope_of (query.rs:232-234), collect_copied_tables_in (query.rs:370-372) and collect_copied_tables_from (query.rs:406-408), and rewrite_join_conditions (query.rs:181-184) walks the same shape inline; delete_tables / delete_tables_mut in statement.rs are another by-ref/by-mut pair. Each copy is a place a future TableFactor variant (PIVOT/UNPIVOT, TASK-0191) must be added independently — collect_copied_tables_from already handles Pivot/Unpivot/MatchRecognize while scope_of and rewrite_derived_tables do not, which is exactly the drift the duplication invites.

**Why it matters**: Coverage fixes land in one walker and miss the others, which in this module means a new silent scope hole.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A `factors(&TableWithJoins) -> impl Iterator<Item=&TableFactor>` and `factors_mut` helper on the query module replaces the inline chains
- [ ] #2 NestedJoin/Pivot/Unpivot/MatchRecognize descent is expressed once and shared by scope_of, rewrite_derived_tables and collect_copied_tables_from
<!-- AC:END -->
