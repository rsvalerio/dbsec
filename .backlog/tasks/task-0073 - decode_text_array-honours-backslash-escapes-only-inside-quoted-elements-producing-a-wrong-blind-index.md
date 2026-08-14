---
id: TASK-0073
title: >-
  decode_text_array honours backslash escapes only inside quoted elements,
  producing a wrong blind index
status: Done
assignee: []
created_date: '2026-08-13 20:19'
updated_date: '2026-08-14 06:59'
labels:
  - code-review-rust
  - correctness
  - encrypt-path
dependencies: []
modified_files:
  - crates/proxy/src/encrypt.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/encrypt.rs:1306`

**What**: PostgreSQL's `array_in` treats `\` as an escape anywhere in an element, quoted
or not. The unquoted branch of `decode_text_array` scans to the next `,` and keeps the
bytes verbatim. `{a\,b}` (one element `a,b` to PostgreSQL) is decoded as two elements
`a\` and `b`; `{\\x616263}` (element `\x616263` -> bytes `abc`) is decoded as the literal
9 bytes because `text_plaintext` only strips a single-backslash `\x` prefix.

**Why it matters**: both cases re-encode into a well-formed `bytea[]` of indexes for
values nobody stored, so the statement returns no rows or wrong rows with no signal —
precisely the outcome `index_array`'s doc comment says must never be produced. The
quoted branch already un-escapes; the unquoted branch should too, or should return
`None` (fail closed to the refusal path) when it sees a backslash.

**Origin**: /code-review high over 8ed2fd4^..d138171 (wave 10, TASK-0062).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 An element containing a backslash escape is either decoded as PostgreSQL decodes it, or refused
- [ ] #2 Round-trip tests cover unquoted escaped commas and unquoted \x-prefixed elements
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Fixed: the bare-element branch now escapes with a backslash exactly as the quoted one does, tracks whether an escape occurred so NULL vs the string "NULL" is decided correctly, and trims only unescaped trailing whitespace. Every case verified against a live PostgreSQL 16 (array_in): {a\,b} is one element; {\NULL,NULL} is "NULL" then NULL; {a\ } keeps its space; {\x616263}::bytea[] is x616263 and {\\x616263}::bytea[] is abc. The pre-existing test asserted the last of those wrongly and was corrected.
<!-- SECTION:NOTES:END -->
