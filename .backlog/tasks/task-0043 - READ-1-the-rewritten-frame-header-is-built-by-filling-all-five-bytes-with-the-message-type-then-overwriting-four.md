---
id: TASK-0043
title: >-
  READ-1: the rewritten frame header is built by filling all five bytes with the
  message type, then overwriting four
status: To Do
assignee:
  - TASK-0051
created_date: '2026-08-11 19:37'
updated_date: '2026-08-11 22:42'
labels:
  - code-review-rust
  - readability
dependencies: []
modified_files:
  - crates/proxy/src/session.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/session.rs:168-169`

**What**:

```rust
let mut new_header = [msg_type; pgwire::FRAME_HEADER_LEN];
new_header[1..].copy_from_slice(&(4 + new_body.len() as i32).to_be_bytes());
```

The array is initialised with `msg_type` in all five positions purely so that position 0 ends up holding it; the next line immediately overwrites the other four. The construction is correct, but it reads as a bug — the obvious interpretation of `[msg_type; 5]` is "a five-byte header of message types", and the reader has to hold both lines in mind to see that only `new_header[0]` survives.

The literal `4` is also unexplained here, though `pgwire`'s module docs (`crates/core/src/pgwire.rs:7-8`) define it as the length field counting itself.

**Why it matters**: This is the one place in the relay that synthesises a wire frame from scratch, in a function whose doc comment stresses that a wrong length "desyncs the relay" — so it is a spot where a future reader needs to be able to check the byte layout at a glance rather than reconstruct it. Writing the two fields separately (`new_header[0] = msg_type;` after a zeroed array, or a small `encode_frame_header(msg_type, len)` helper next to `frame_body_len` in `pgwire`, which already owns the inverse) makes the layout self-evident and puts the `+ 4` convention beside the parser that applies the matching `- 4`. Note [[task-0013]] already targets the unchecked `as i32` on the same expression; this is about the surrounding construction, and the two are worth fixing together.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The frame header is built so that each field is written exactly once and the byte layout is readable without cross-referencing two lines
- [ ] #2 The +4 length convention is either named by a shared helper or carries a comment pointing at pgwire::frame_body_len
- [ ] #3 Existing relay tests still assert the rewritten header bytes for a transformed frame
<!-- AC:END -->
