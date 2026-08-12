---
id: TASK-0033
title: >-
  DUP-1: the nullable length-prefixed value loop is copy-pasted between the
  DataRow and Bind codecs
status: To Do
assignee:
  - TASK-0055
created_date: '2026-08-11 19:26'
updated_date: '2026-08-11 22:42'
labels:
  - code-review-rust
  - duplication
  - pgwire
dependencies: []
modified_files:
  - crates/core/src/pgwire.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/core/src/pgwire.rs:102-107`, `crates/core/src/pgwire.rs:189-194`, `crates/core/src/pgwire.rs:120-128`, `crates/core/src/pgwire.rs:226-234`

**What**: DataRow and Bind encode their values with the same wire construct — `i32` length, `-1` for NULL, then that many bytes — and the code for it exists twice in each direction, byte for byte.

Decode, `parse_data_row:102-107` and `parse_bind:189-194`:

```rust
let len = i32::from_be_bytes(take(&mut body, 4)?.try_into().expect("4 bytes"));
match len {
    -1 => values.push(None),
    0.. => values.push(Some(take(&mut body, len as usize)?)),
    _ => return Err(Error::MalformedBackend),
}
```

Encode, `encode_data_row:120-128` and `encode_bind:226-234`: the same `match value { None => -1i32, Some(v) => len then bytes }` block.

**Why it matters**: Four copies of one protocol rule. The concern is not the line count — it is that a change to how a nullable value is framed has to be made in four places, and a fix applied to three of them still compiles and still passes most tests. TASK-0032 is exactly such a change: it touches the two encode copies and has to find both. The DataRow path is well covered by the fuzz target while the Bind path shares fewer assertions, so a divergence between them is not guaranteed to show up.

The extraction is small and obvious: `take_nullable(buf: &mut &[u8]) -> Result<Option<&[u8]>, Error>` and `push_nullable(out: &mut Vec<u8>, value: Option<&[u8]>)`, alongside the existing private `take`/`take_i16`/`skip_cstr` helpers, which is already where this file puts shared framing primitives.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A single private helper decodes a nullable length-prefixed value, used by both parse_data_row and parse_bind
- [ ] #2 A single private helper encodes a nullable length-prefixed value, used by both encode_data_row and encode_bind
- [ ] #3 Existing pgwire unit tests, property tests and fuzz targets still pass unchanged
<!-- AC:END -->
