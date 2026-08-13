---
id: TASK-0072
title: >-
  A read-path refusal discards a following batch's results when the refused
  batch ended in Flush
status: Done
assignee: []
created_date: '2026-08-13 20:19'
updated_date: '2026-08-13 21:29'
labels:
  - code-review-rust
  - correctness
  - read-path
dependencies: []
modified_files:
  - crates/proxy/src/rows.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/rows.rs:206`

**What**: `on_frame` sets `refusing` and then drops every frame until the first `b'Z'`.
If a client pipelines batch A terminated by `Flush` (no Sync yet) and batch B terminated
by `Sync`, a refusal inside A consumes all of B's RowDescription/DataRow/CommandComplete
and clears `refusing` on B's ReadyForQuery.

**Why it matters**: the client gets one ErrorResponse for A and then a ReadyForQuery,
with B's results silently gone even though B ran on the server — its response queue is
now one batch out of step. The rest of the file is careful about exactly this class of
Flush/Sync bookkeeping (see the `SessionPortals::copy_data` doc), so the gap looks
unintended.

**Origin**: /code-review high over 8ed2fd4^..d138171 (wave 10, TASK-0064).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A refusal inside a Flush-terminated batch does not consume a following batch's results
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Dissolved by TASK-0071 (a3515d7) rather than fixed on its own terms. The finding was a defect in discard_until_ready, which consumed frames up to the next ReadyForQuery; a refusal now closes the session instead, so that loop is deleted and there is nothing left to consume a following Flush-terminated batch. Verified: no discard state remains in rows.rs.
<!-- SECTION:NOTES:END -->
