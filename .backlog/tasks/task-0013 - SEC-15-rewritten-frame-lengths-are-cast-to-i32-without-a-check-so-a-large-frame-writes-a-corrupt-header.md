---
id: TASK-0013
title: >-
  SEC-15: rewritten frame lengths are cast to i32 without a check, so a large
  frame writes a corrupt header
status: Done
assignee:
  - TASK-0051
created_date: '2026-08-11 19:13'
updated_date: '2026-08-12 10:46'
labels:
  - code-review-rust
  - security
  - session
dependencies: []
modified_files:
  - crates/proxy/src/session.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/session.rs:167-172`

**What**: When a transform returns a replacement body, the relay builds the new header with an unchecked cast:

```rust
let mut new_header = [msg_type; pgwire::FRAME_HEADER_LEN];
new_header[1..].copy_from_slice(&(4 + new_body.len() as i32).to_be_bytes());
```

Nothing verifies that `new_body.len()` fits in an `i32`, or that the result stays under `pgwire::MAX_MESSAGE_LEN`. The inbound side is validated (`frame_body_len` rejects anything over 1 GiB) but the *outbound* side is not, and rewritten bodies are systematically larger than what came in:

- `encrypt.rs:145` hex-encodes a sealed BYTEA parameter into `\x…`, roughly 2x the sealed bytes, which themselves carry envelope and blind-index overhead.
- `rows.rs:93` does the same on the read path.

So a body just under the 1 GiB inbound limit can produce a replacement over `i32::MAX`. In release builds the `as i32` truncates silently (and the `4 +` wraps) — the header carries a negative or nonsensical length, which the peer reads as a protocol violation or, worse, as a short frame that desyncs the stream the relay is explicitly designed not to desync.

**Why it matters**: The input is entirely client-controlled and the failure is silent under `--release`, which is the profile that ships. The whole point of the `frame_body_len` validation and the "aborting desynced relay" error path is that a length mismatch must never reach the wire; this is the one place a length is written without that discipline. The fix is a checked conversion that fails the session the same way an inbound bad length does.

<!-- scan confidence: candidates to inspect -->
Related unchecked `as i32` length casts exist in `crates/core/src/pgwire.rs` (`encode_data_row`, `encode_bind`) — out of scope for this crate review but worth the same treatment.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 The rewritten body length is checked against MAX_MESSAGE_LEN and i32 range before the header is written; overflow fails the session with a clear error rather than truncating
- [x] #2 The header construction no longer relies on filling the array with msg_type and overwriting bytes 1..5 — it reads as what it is
- [x] #3 A test covers a transform returning an oversized body and asserts the session errors instead of emitting a corrupt header
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Fixed in wave TASK-0051 (branch code-review/TASK-0051), together with TASK-0043 — both target the same three lines of `relay`.

- AC #1 + #2: the `[msg_type; 5]`-then-overwrite construction is replaced by `session::encode_frame_header(msg_type, body_len)`, which does `checked_add(4)`, rejects anything over `pgwire::MAX_MESSAGE_LEN`, and uses `i32::try_from` instead of `as i32`. Overflow fails the session with the new `Error::FrameTooLarge { msg_type, body_len, max }` — the same fail-closed shape as an inbound bad length.
- AC #3: `session::tests::relay_fails_closed_on_an_oversized_rewritten_body` drives `relay` with a transform returning a `MAX_MESSAGE_LEN + 1` body and asserts `Error::FrameTooLarge` with nothing written to the writer. `frame_header_rejects_oversized_bodies_instead_of_truncating` covers the boundary either side (MAX-4 ok, MAX / i32::MAX / usize::MAX rejected).

The related unchecked `as i32` casts in `crates/core/src/pgwire.rs` (`encode_data_row`, `encode_bind`) noted in the description are out of this wave's file scope and are already the subject of wave6 (TASK-0055, pgwire codec hardening).
<!-- SECTION:NOTES:END -->
