---
id: TASK-0280
title: >-
  CL-3: A refused Parse/Bind mid-batch answers the client immediately and
  swallows the Sync, so forwarded earlier statements commit late and desync the
  client
status: Triage
assignee: []
created_date: '2026-08-22 00:46'
labels:
  - code-review-rust
  - clean-code
dependencies: []
modified_files:
  - crates/proxy/src/encrypt/frame.rs
  - crates/proxy/src/session.rs
  - crates/proxy/src/portal.rs
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/encrypt/frame.rs:149`

**What**: frame.rs:149-156 (and the Bind refusals at 261 and 306) set `awaiting_sync`, reply with an ErrorResponse through `FrameAction::Reply` (session.rs:660, written straight to the client's writer) and then `discard_until_sync` (frame.rs:324-336) drops every frame up to Sync and answers the Sync with a synthesized ReadyForQuery *without forwarding it*. The comment claims 'the backend has no work queued for this batch', which is only true when the refused message is the first of its batch. In a pipelined batch — `P1/B1/E1/P2(refused)/B2/E2/S`, which is what npgsql NpgsqlBatch, pgx SendBatch, libpq pipeline mode and JDBC batches put on the wire — P1/B1/E1 were already forwarded: the backend executes statement 1 inside an implicit transaction, buffers its ParseComplete/BindComplete/CommandComplete (pq_flush only happens at ReadyForQuery), and never receives a Sync. Meanwhile the client has already been handed `E` + `Z('I')` and considers the batch finished. On the client's next batch the backend flushes statement 1's stale responses ahead of the new ones (client-side protocol desync: JDBC 'unexpected packet type', npgsql mis-attributes results) and commits statement 1 together with that unrelated batch. PostgreSQL's own behaviour for an error mid-batch is to roll statement 1 back with the implicit transaction. The proxy's pending queue (`Execute1` left in portal.rs with no `Batch` marker) happens to stay consistent, so nothing on the proxy side detects it.

**Why it matters**: A batch the client was told failed partially commits at an arbitrary later point, and the response stream the client sees is out of order. The 'E' status trick in `ready_for_query` (frame.rs:343) does not help in the implicit-transaction case because the backend holds no error state at all.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 When a refusal happens after any frame of the current batch has already been forwarded, the proxy puts the backend into the same error state PostgreSQL would be in (e.g. forward a deliberately failing Parse/Bind so the backend errors, skips to Sync and rolls the implicit transaction back), forwards the Sync, and relays/replaces the backend's ErrorResponse+ReadyForQuery instead of synthesizing its own; a synthesized reply is only used when nothing of the batch reached the backend
- [ ] #2 Replies do not overtake in-flight responses: an ErrorResponse answered for message N of a batch reaches the client only after the backend's responses to messages 1..N-1 of that batch
- [ ] #3 Tests: a pipelined batch with an unrefused Execute followed by a refused Parse yields, in order, the first statement's responses, the error, one ReadyForQuery, and the first statement's effect is rolled back (e2e) — for both the extended protocol and two pipelined simple Queries
<!-- AC:END -->
