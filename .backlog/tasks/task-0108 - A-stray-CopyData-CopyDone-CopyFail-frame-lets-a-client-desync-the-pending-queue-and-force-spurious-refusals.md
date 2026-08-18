---
id: TASK-0108
title: >-
  A stray CopyData/CopyDone/CopyFail frame lets a client desync the pending
  queue and force spurious refusals
status: Done
assignee:
  - TASK-0124
created_date: '2026-08-14 18:16'
updated_date: '2026-08-17 20:56'
labels:
  - security-review
  - protocol
  - reliability
dependencies: []
modified_files:
  - crates/proxy/src/portal.rs
  - crates/proxy/src/encrypt.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/portal.rs:292` (`copy_data`), `:355` (`batch_answered`); `crates/proxy/src/encrypt.rs:311` (`on_frame` copy dispatch).

**What**: `QueryRewriter::on_frame` calls `self.portals.copy_data()` unconditionally on any client `'d' | 'c' | 'f'` frame, without knowing whether the backend is actually in copy-in mode — it cannot know, because `CopyInResponse` travels upstream→client. PostgreSQL silently ignores `d`/`c`/`f` received outside copy mode (no ErrorResponse, no ReadyForQuery), so these frames produce **no backend response**. Meanwhile `copy_data()` pops trailing `Pending::Batch` markers after the last `Execute`.

**Why it matters**: a client can therefore delete `Batch` markers at will; on the next real `ReadyForQuery`, `batch_answered` over-consumes into the *following* batch's `Describe`/`Execute` expectations, so subsequent DataRows are misattributed. In every traced sequence this **fails closed** — misattributed rows resolve to `RowSource::Undescribed`/`LastDescription` with `described == None` and hit `Error::UndescribedRow`, or apply protected positions to the wrong row and hit a crypto error → `RefuseAndClose`/session-drop. So there is no plaintext/ciphertext leak (the `described = None` reset on every `'C'`/`'Z'` is the safety net), but it is a clean client-driven forced-desync / self-inflicted DoS that violates the module's stated invariant that the shared queue "stays aligned without any further synchronisation" (`portal.rs:16-23`), and it would compound any future attribution bug. Not covered by the existing `copy_data` tasks, which address only the legitimate copy-in `Sync` case.

**Fix shape**: track whether a copy-in is actually in progress (set on observing `CopyInResponse` in the upstream→client relay, cleared on `CopyDone`/`CopyFail`/error), and have `on_frame` only route `'d'/'c'/'f'` through `copy_data()` while that flag is set; ignore or reject stray copy frames otherwise so they cannot mutate the pending queue.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 The proxy only treats `d`/`c`/`f` as copy-in payload while a `CopyInResponse` has been observed and not yet completed
- [x] #2 A stray copy frame outside copy mode cannot pop `Pending::Batch` markers
- [x] #3 A test interleaves stray `CopyData` before a real batch and asserts the following batch's rows are still attributed correctly
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Fixed in wave TASK-0124: SessionPortals gains a copy_in flag set by the read direction on CopyInResponse/CopyBothResponse (session::note_backend_state, which also records the transaction status) and cleared on CopyDone/CopyFail or any ReadyForQuery. SessionPortals::copy_data now takes the message type and returns without touching the queue unless a copy is really in progress, so a stray d/c/f can no longer pop Pending::Batch markers; the frame is still relayed, matching what PostgreSQL does with it. Tests: portal::a_stray_copy_frame_outside_copy_mode_moves_nothing (strays before and inside a batch, following batch still attributed), portal::copy_mode_ends_with_the_copy_and_a_later_sync_is_answered, session::the_read_direction_records_the_backends_copy_and_transaction_state.
<!-- SECTION:NOTES:END -->
