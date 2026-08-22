---
id: TASK-0282
title: >-
  SEC-11: decode_text_array accepts literals array_in rejects (empty bare
  elements, quotes inside a bare element), turning a client syntax error into a
  valid blind-index query
status: Triage
assignee: []
created_date: '2026-08-22 00:46'
labels:
  - code-review-rust
  - security
dependencies: []
modified_files:
  - crates/proxy/src/encrypt/array.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/encrypt/array.rs:236`

**What**: `unquoted_element` (crates/proxy/src/encrypt/array.rs:236-267) scans to the next unescaped comma and accepts whatever it finds, so `{a,,b}`, `{a,}`, `{,a}` each yield an empty-string element and `{a"b"}` / `{a"b}` yield the element `a"b"` / `a"b` — shapes PostgreSQL's `array_in` refuses with `malformed array literal`. `decode_text_array` (array.rs:160-188) then hands those elements to `index_array`, which re-encodes them as a well-formed `bytea[]` of blind indexes (array.rs:302-319). The module docs (array.rs:7-10, 153-159) commit to 'fail rather than guess' and to returning `None` for anything it 'cannot decode faithfully'. The property tests (array.rs:457-552) only check round-trips of the encoder's own output and non-panicking on noise, so no test pins agreement with `array_in` on rejected shapes.

**Why it matters**: A statement the server would have rejected as a syntax error instead executes as a valid `= ANY(bytea[])` over the blind index of `""` (or of a value containing stray quotes), returning rows with an empty protected value — a semantics divergence between proxy and server of the kind this codec is explicitly written to avoid. Impact is bounded (the client chose the literal), hence low.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 `unquoted_element` returns `None` for an empty bare element and for a double-quote byte inside a bare element, matching `array_in`'s rejections
- [ ] #2 `decode_text_array` refuses `{a,,b}`, `{a,}`, `{,a}`, `{a"b"}` and `{"a"b}`; the `refused` list in `the_array_codec_reads_what_postgres_writes_and_refuses_the_rest` is extended with them
- [ ] #3 A property asserts that any text literal the decoder accepts contains no bare element that is empty or carries an unescaped `"`
<!-- AC:END -->
