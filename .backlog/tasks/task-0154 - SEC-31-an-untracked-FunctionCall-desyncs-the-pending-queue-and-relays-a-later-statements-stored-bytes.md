---
id: TASK-0154
title: >-
  SEC-31: an untracked FunctionCall desyncs the pending queue and relays a later
  statement's stored bytes
status: To Do
assignee:
  - TASK-0179
created_date: '2026-08-19 08:28'
updated_date: '2026-08-19 09:01'
labels:
  - code-review-rust
  - protocol
dependencies: []
modified_files:
  - crates/proxy/src/encrypt/mod.rs
  - crates/proxy/src/portal.rs
  - crates/proxy/src/rows.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/encrypt/mod.rs:507`

**What**: `on_frame` has no arm for the legacy `FunctionCall` (`'F'`); it falls to
`_ => Ok(FrameAction::Relay)` and queues nothing. PostgreSQL answers `'F'` with
FunctionCallResponse **and a ReadyForQuery**. The read side handles `'V'` without touching the
queue, then `'Z'` calls `batch_answered`, which pops until and including the first `Batch`
marker — consuming a pipelined batch's entries. Every subsequent response is matched to the
wrong expectation, and a RowDescription is attributed to a following statement's id.

The dangerous direction: a protected position of the executing statement that the
mis-attributed `Described` does not cover is relayed in its stored form — for a mask-only
column, the plaintext the mask exists to hide, with no warning and no refusal. Reachable only
under the default `warn` (under `reject` the `'V'` frame is refused first).

**Why it matters**: `portal.rs`'s module docs establish that the queue must only move for
frames the backend actually answers — the reason `copy_data` refuses to act on a stray copy
frame. `'F'` is the one client message that owes a ReadyForQuery and is not recorded.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 'F' either records a Pending::Batch so its ReadyForQuery settles its own marker, or is refused outright, consistently with 'V'
- [ ] #2 A test pipelines FunctionCall ahead of a Parse/Describe/Bind/Execute/Sync batch and asserts the batch's RowDescription lands on its own Execute
<!-- AC:END -->
