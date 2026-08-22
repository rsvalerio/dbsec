---
id: TASK-0213
title: >-
  SEC-15: a negative i16 count in RowDescription, DataRow, Bind or the Bind
  result-format section is silently accepted as zero instead of being rejected
  as malformed
status: Triage
assignee: []
created_date: '2026-08-21 19:48'
labels:
  - code-review-rust
  - security
dependencies: []
modified_files:
  - crates/pgwire/src/lib.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/pgwire/src/lib.rs:164-166` (`parse_row_description`), `:185-187` (`parse_data_row`), `:294-302` (`parse_bind`, both `format_count` and `param_count`), `:270-272` (`BindMessage::result_format_codes`)

**What**: Each parser reads an `i16` count and then does `Vec::with_capacity(count.max(0) as usize)` followed by `for _ in 0..count`. For a negative count (`0x8000..=0xFFFF` on the wire) the `.max(0)` hides the sign and the range is empty, so the parser returns `Ok(vec![])` — a DataRow with count `-1` and an empty body parses as a zero-column row; a Bind with `format_count = -5` parses as "all text". The protocol defines these as non-negative counts; a negative value is a malformed frame, and the crate's own encoders (`wire_count`) refuse to emit one.

**Why it matters**: The parsers are the proxy's first line against a peer that is lying about frame shape. Accepting a sign-flipped count as zero means the proxy's view of a frame (`0` columns/params) can diverge from what a stricter or looser peer on the other side would compute from the same bytes, which is the classic desync primitive for a protocol proxy: the rewritten frame relays a "zero parameter" Bind while the real server would refuse it, or vice versa. The crate advertises `decode(encode(x)) == x`; this is an input set where `decode` succeeds but no `encode` could have produced it.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A negative count in any of the four parsers returns Err (the malformed variant for that direction), never Ok(empty)
- [ ] #2 The i16 count is narrowed once through a helper (e.g. take_count -> Result<usize, Error>) so the .max(0) as usize pattern disappears from all four sites
- [ ] #3 Unit tests cover count = -1 and count = i16::MIN for RowDescription, DataRow, Bind parameter/format counts, and result_format_codes
- [ ] #4 The proptest in crates/pgwire/tests/props.rs or the fuzz target asserts that any Ok parse re-encodes to the identical bytes (round-trip in the other direction)
<!-- AC:END -->
