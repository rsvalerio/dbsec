---
id: TASK-0215
title: >-
  TEST-9: the in-tree property tests never touch parse_parse, parse_bind,
  encode_bind or result_format_codes, and result_format_codes / format_code /
  take_cstr have no direct test at all
status: Triage
assignee: []
created_date: '2026-08-21 19:48'
labels:
  - code-review-rust
  - testing
dependencies: []
modified_files:
  - crates/pgwire/tests/props.rs
  - crates/pgwire/src/lib.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/pgwire/tests/props.rs:8-41`, `crates/pgwire/src/lib.rs:268-276` (`result_format_codes`), `:283-289` (`format_code`), `:351-356` (`take_cstr`), `:223-227` (`parse_parse`), `:291-348` (`parse_bind`/`encode_bind`)

**What**: The crate's contract (lib.rs:4, props.rs:1-3) is "no arbitrary byte string may make a parser panic or over-read, and an encoded frame must parse back to what went in". The four proptests enforce that for `frame_body_len`, `startup_body_len`, `parse_row_description` and `parse_data_row` only. The frontend parsers that consume *client* bytes — `parse_parse`, `parse_bind`, `BindMessage::result_format_codes` — and the `encode_bind`/`parse_bind` round-trip are absent from `tests/props.rs`. They are exercised by `fuzz/fuzz_targets/pgwire.rs`, but `fuzz/` is excluded from the workspace, so `cargo test` / CI never runs it, and even that target never calls `result_format_codes`. Beyond the property layer, three public items have no test of their own: `result_format_codes` (no unit test anywhere), `format_code` (only reached through `param_format`), and `take_cstr` (public, only reached indirectly). The existing `parses_row_description`, `parse_message_roundtrips` and `data_row_roundtrips` tests assert malformed input with bare `.is_err()` rather than the variant (TEST-11).

**Why it matters**: These are the parsers on the untrusted side of the proxy (SEC-37 scope), and the unit tests only cover the happy path plus a one-byte truncation. A regression that makes `parse_bind` panic on, say, a param length of `i32::MAX` (currently safe only because `take` uses `split_at_checked`) would pass `cargo test` today. `result_format_codes` was added for SEC-31 (TASK-0147) and drives how the read path decodes row keys; it is untested in-tree.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 tests/props.rs gains never-panic properties for parse_parse, parse_bind and result_format_codes over arbitrary bytes (0..512)
- [ ] #2 tests/props.rs gains an encode_bind -> parse_bind round-trip property (portal, statement, formats, params, raw result_formats) and an encode_parse -> parse_parse round-trip
- [ ] #3 result_format_codes has unit tests for the empty section, one code, N codes and a truncated section; format_code has direct tests for the three shorthand arms; take_cstr has a test for missing terminator and empty string
- [ ] #4 Malformed-input assertions in lib.rs tests use assert_matches!/matches! on the specific Error variant instead of is_err()
- [ ] #5 The fuzz target also calls result_format_codes on every Ok(bind)
<!-- AC:END -->
