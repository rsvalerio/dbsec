---
id: TASK-0211
title: >-
  ERR-2: Error::MalformedBackend ("malformed backend message") is the variant
  every frontend-message parser returns, so a garbage Parse or Bind from a
  client is reported as a backend fault
status: Triage
assignee: []
created_date: '2026-08-21 19:47'
labels:
  - code-review-rust
  - error-handling
dependencies: []
modified_files:
  - crates/pgwire/src/lib.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/pgwire/src/lib.rs:32` (variant), `:223-227` (`parse_parse`), `:291-305` (`parse_bind`), `:268-276` (`BindMessage::result_format_codes`), `:351-374` (`take_cstr`, `take`, `take_nullable`)

**What**: The only "malformed" variant in the crate's `Error` is `MalformedBackend`, whose `Display` is `"malformed backend message"`. It is produced by the shared helpers (`take`, `take_cstr`, `take_nullable`, `take_i16`) and therefore by every parser — including `parse_parse` and `parse_bind`, which decode *frontend* (client → server) messages, and `result_format_codes`, which decodes a section of a client Bind. A client that sends a truncated or unterminated Parse/Bind makes the proxy log and refuse with a message that blames the backend. `result_format_codes` even documents the variant as "when the section is truncated" without saying the bytes came from the client.

**Why it matters**: The error is the operator's only signal when a session is refused. A misattributed direction sends them to the wrong side of the proxy (checking the PostgreSQL server instead of the driver), and a future caller that matches on `MalformedBackend` to decide "the backend is lying to us, drop the upstream" will act on client-originated garbage. `Error` is `#[non_exhaustive]`, so adding a direction-carrying variant is non-breaking.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Malformed frontend messages (Parse, Bind, Bind result-format section) surface through a variant whose Display names the frontend/client, not the backend (e.g. a MalformedFrontend variant or a Malformed { direction } shape)
- [ ] #2 The shared take_* helpers either take the direction as a parameter or the public parsers map the helper error to the right variant
- [ ] #3 Doc comments on parse_parse, parse_bind and result_format_codes name the variant they return
- [ ] #4 A test asserts that a truncated Bind and an unterminated Parse produce the frontend-attributed variant and that a truncated RowDescription still produces MalformedBackend
<!-- AC:END -->
