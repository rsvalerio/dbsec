---
id: TASK-0108
title: >-
  A stray CopyData/CopyDone/CopyFail frame lets a client desync the pending
  queue and force spurious refusals
status: Triage
assignee: []
created_date: '2026-08-14 18:16'
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
- [ ] #1 The proxy only treats `d`/`c`/`f` as copy-in payload while a `CopyInResponse` has been observed and not yet completed
- [ ] #2 A stray copy frame outside copy mode cannot pop `Pending::Batch` markers
- [ ] #3 A test interleaves stray `CopyData` before a real batch and asserts the following batch's rows are still attributed correctly
<!-- AC:END -->
