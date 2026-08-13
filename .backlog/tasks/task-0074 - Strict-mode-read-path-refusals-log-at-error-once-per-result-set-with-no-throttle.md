---
id: TASK-0074
title: >-
  Strict-mode read-path refusals log at error! once per result set with no
  throttle
status: Triage
assignee: []
created_date: '2026-08-13 20:19'
labels:
  - code-review-rust
  - observability
  - read-path
dependencies: []
modified_files:
  - crates/proxy/src/rows.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/rows.rs:220`

**What**: the warn path deliberately throttles with `warned_stale` ("one per result set
would be a log flood for exactly as long as the migration goes unnoticed"). Now that a
strict-mode `StaleColumnMap` returns the client an error instead of dropping the
connection, the session survives and a client retrying the statement in a loop produces
one `error!` line per attempt.

**Why it matters**: the same flood the warn path was built to avoid, on the path that
previously emitted at most one line per session because the session ended.

**Origin**: /code-review high over 8ed2fd4^..d138171 (wave 10, TASK-0064).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A client retrying a refused statement in a loop does not emit one error line per attempt
<!-- AC:END -->
