---
id: TASK-0032
title: >-
  SEC-15: encode_data_row and encode_bind cast counts and lengths with unchecked
  as, silently emitting a corrupt frame
status: To Do
assignee:
  - TASK-0055
created_date: '2026-08-11 19:26'
updated_date: '2026-08-11 22:42'
labels:
  - code-review-rust
  - security
  - pgwire
dependencies: []
modified_files:
  - crates/core/src/pgwire.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/core/src/pgwire.rs:119`, `crates/core/src/pgwire.rs:124`, `crates/core/src/pgwire.rs:221`, `crates/core/src/pgwire.rs:225`, `crates/core/src/pgwire.rs:231`

**What**: Both encoders narrow `usize` into the wire's fixed-width fields with a plain `as`:

```rust
out.extend_from_slice(&(values.len() as i16).to_be_bytes());   // 119
out.extend_from_slice(&(v.len() as i32).to_be_bytes());        // 124
out.extend_from_slice(&(param_formats.len() as i16).to_be_bytes()); // 221
out.extend_from_slice(&(params.len() as i16).to_be_bytes());   // 225
out.extend_from_slice(&(p.len() as i32).to_be_bytes());        // 231
```

Above 32767 values the count wraps — often to a negative number, which the peer's parser reads as a malformed message or, worse, as a plausible smaller count with trailing garbage. Above 2 GiB, a value length wraps negative; `-1` is the wire encoding for SQL NULL, so a sufficiently large value would encode as a null column rather than as data.

**Why it matters**: Not reachable through the proxy today, and worth being explicit about why: `parse_data_row`/`parse_bind` read their counts as `i16`, so a parse-then-reencode roundtrip can never exceed 32767, `MAX_MESSAGE_LEN` caps a frame at 1 GiB, and PostgreSQL itself allows at most 1664 columns. The fuzz target at `fuzz/fuzz_targets/pgwire.rs` proves the roundtrip property holds for parsed input.

The finding is about the API contract rather than a live bug. These are `pub` functions on a library crate, and their signatures accept slices of any length with nothing in the type or the docs saying otherwise — so the guarantee lives entirely in the calling code, one crate away, and disappears the moment a caller constructs a row rather than reparsing one. That is exactly the class SEC-15 targets: a silent truncation that turns a caller's programming error into corrupt bytes on the wire instead of an error. TASK-0013 is the same rule on the proxy's frame-length cast.

Cheapest honest fix: `i16::try_from(values.len())` / `i32::try_from(v.len())` returning `Result`, which makes the encoders fallible and forces the constraint into the signature. If keeping them infallible is preferred, a `debug_assert!` plus a documented precondition on each function is acceptable — but the precondition must be written down.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Column counts, format counts and value lengths are converted with try_from rather than as, or the functions document an explicit precondition backed by a debug_assert
- [ ] #2 If the encoders become fallible, callers in crates/proxy handle the new Result
- [ ] #3 A test covers the over-limit case for at least the column-count path
<!-- AC:END -->
