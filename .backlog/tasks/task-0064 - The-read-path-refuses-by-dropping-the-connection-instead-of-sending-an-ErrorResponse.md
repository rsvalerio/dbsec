---
id: TASK-0064
title: >-
  The read path refuses by dropping the connection instead of sending an
  ErrorResponse
status: To Do
assignee:
  - TASK-0066
created_date: '2026-08-12 17:01'
updated_date: '2026-08-12 18:42'
labels:
  - code-review-rust
  - read-path
  - error-handling
dependencies: []
modified_files:
  - crates/proxy/src/rows.rs
  - crates/proxy/src/session.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/rows.rs`, `crates/proxy/src/session.rs`

**What**: The read path now has two deliberate fail-closed refusals — `Error::UndescribedRow` (a DataRow the proxy cannot tie to any described statement) and `Error::StaleColumnMap` (a result column named like a protected one that the resolved map does not cover, under `on_unprotected = "reject"`). Both return `Err` out of `RowDecryptor::on_frame`, which aborts the relay and closes the socket.

The write path does not behave this way. Wave 0 (TASK-0049) gave every refusal there a well-formed PostgreSQL ErrorResponse (SQLSTATE 42501) plus ReadyForQuery, so the client sees a real statement-level error and the session survives. The read path's refusals give the client a bare connection reset: no SQLSTATE, no message, and `tokio_postgres::Error::Closed` rather than a `DbError`. The proxy's own reason is only in its log.

**Why it matters**: An operator running `on_unprotected = "reject"` gets a dropped connection where the write path would have given them an actionable error, and application retry logic will read it as a network fault rather than a policy refusal. It also makes the two halves of the same setting behave differently, which the README now has to explain rather than state.

Harder than the write path: the refusal can land in the middle of a result set the client is already reading, so it needs the backend's own semantics for an error mid-DataRow-stream (ErrorResponse, then the frames up to the next ReadyForQuery), and the read path has no equivalent of the write path's `awaiting_sync` state to drive that.

Related: the read path's fail-closed reading of a suspect column is currently controlled by `on_unprotected`, which is otherwise a write-path setting. Whether it deserves its own knob is worth deciding at the same time.

**Origin**: discovered during TASK-0050 while fixing TASK-0044 and TASK-0039.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A read-path refusal reaches the client as a PostgreSQL ErrorResponse with a SQLSTATE and a message, not as a closed socket
- [ ] #2 The session survives a refusal the way it does on the write path, resynchronising at the next ReadyForQuery
- [ ] #3 Whether the read path's fail-closed reading needs a setting separate from on_unprotected is decided and recorded
<!-- AC:END -->
