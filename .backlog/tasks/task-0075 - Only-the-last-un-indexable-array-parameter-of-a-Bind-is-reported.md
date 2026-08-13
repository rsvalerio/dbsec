---
id: TASK-0075
title: Only the last un-indexable array parameter of a Bind is reported
status: Triage
assignee: []
created_date: '2026-08-13 20:19'
labels:
  - code-review-rust
  - observability
  - encrypt-path
dependencies: []
modified_files:
  - crates/proxy/src/encrypt.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/encrypt.rs:366`

**What**: `refusal` is a single `Option` assigned inside the parameter loop, so a Bind
with two `= ANY($n)` arrays that both fall back reports only the second column.

**Why it matters**: the operator fixing the statement sees one of the two sites, fixes
it, and hits the second on the next run.

**Origin**: /code-review high over 8ed2fd4^..d138171 (wave 10, TASK-0062).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A Bind with two un-indexable array parameters names both in the warn log and the refusal message
<!-- AC:END -->
