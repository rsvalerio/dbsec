---
id: TASK-0168
title: 'FN-1: decode_text_array is an 88-line hand-written scanner at depth 7'
status: Done
assignee:
  - TASK-0180
created_date: '2026-08-19 08:32'
updated_date: '2026-08-19 10:23'
labels:
  - code-review-rust
  - complexity
dependencies: []
modified_files:
  - crates/proxy/src/encrypt/array.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/encrypt/array.rs:159`

**What**: one `loop` containing two inline element parsers (quoted, unquoted) plus the separator
scan, at brace depth 7. Unchanged by the split, but it moved into a module the split framed as
"the Bind-time codec written to fail rather than guess".

**Why it matters**: this is the only place in the tree that parses raw client-chosen bytes with
hand-rolled index arithmetic (`bytes.get(at + 1)?`,
`value.truncate(value.len() - trailing_space)`). Correctness-criticality argues for lower
cognitive load exactly here, and the two element parsers are independent and extract cleanly.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 decode_text_array is <= 50 lines by extracting quoted_element and unquoted_element helpers
- [x] #2 Max nesting in each is <= 4 and the existing proptests pass unchanged
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
decode_text_array is now 29 lines; quoted_element (21) and unquoted_element (32) were extracted, plus skip_whitespace for the separator scan. Max brace depth in each is 4: the trailing-whitespace bookkeeping that would have made unquoted_element depth 5 became a kept marker (the length through the last escaped byte) plus one take_while trim, which is the same rule stated once. All existing array proptests pass unchanged.
<!-- SECTION:NOTES:END -->
