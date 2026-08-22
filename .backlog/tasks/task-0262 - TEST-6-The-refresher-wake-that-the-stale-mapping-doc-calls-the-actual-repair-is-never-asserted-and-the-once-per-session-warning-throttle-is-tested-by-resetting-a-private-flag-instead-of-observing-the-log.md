---
id: TASK-0262
title: >-
  TEST-6: The refresher wake that the stale-mapping doc calls 'the actual
  repair' is never asserted, and the once-per-session warning throttle is tested
  by resetting a private flag instead of observing the log
status: Triage
assignee: []
created_date: '2026-08-22 00:38'
labels:
  - code-review-rust
  - test
dependencies: []
modified_files:
  - crates/proxy/src/rows.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/rows.rs:2635`

**What**: `check_for_stale_mapping` documents that requesting a re-resolution (rows.rs:807-809, `self.ctx.request_refresh()`) is 'the actual repair' and that the `warn` reading is only a heuristic in front of it, yet no test in the crate awaits `RowContext::refresh_requested()` after a suspect RowDescription (the only caller is `resolve.rs:80`). A suspect 'T' that silently stops waking the refresher would pass the suite. Separately, `a_protected_column_at_an_unresolved_position_is_noticed_not_relayed_silently` (2635-2658), `a_computed_protected_column_is_reported_rather_than_relayed` (2667-2684) and `a_function_call_result_is_not_relayed_through_the_catch_all` (2741-2756) claim to test 'once is enough — the flag is what stops a per-result-set flood' but do so by setting `warned_* = false` on the private field and checking it becomes `true` again, which only re-proves the first warning; none of them sends a second frame with the flag still set and asserts that nothing is logged. `crate::captured_events` (main.rs:200) already exists and is used in the same module (2111) for exactly this shape.

**Why it matters**: Both behaviours are the operational half of the CL-3 fix for silent stale mappings (TASK-0039 / TASK-0111): the refresh wake is what makes the migration get noticed before the next tick, and the throttle is what keeps a long-lived session from flooding the log. Neither can regress visibly today.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A test sends a suspect RowDescription under `warn` and asserts `ctx.refresh_requested()` completes (e.g. current-thread runtime + `now_or_never`), and that an unsuspicious description does not wake it
- [ ] #2 The three 'once per session' tests wrap two consecutive frames in `captured_events` and assert exactly one warning event, without touching `warned_*` directly
- [ ] #3 The `warned_*` fields are no longer written from the test module
<!-- AC:END -->
