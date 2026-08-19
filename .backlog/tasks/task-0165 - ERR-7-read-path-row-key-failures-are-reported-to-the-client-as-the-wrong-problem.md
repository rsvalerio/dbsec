---
id: TASK-0165
title: >-
  ERR-7: read-path row-key failures are reported to the client as the wrong
  problem
status: Done
assignee:
  - TASK-0177
created_date: '2026-08-19 08:31'
updated_date: '2026-08-19 09:37'
labels:
  - code-review-rust
  - error-handling
dependencies: []
modified_files:
  - crates/proxy/src/rows.rs
  - crates/proxy/src/rowkey.rs
  - crates/proxy/src/main.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/rows.rs:742`

**What**: `decrypt_row` builds its row keys with `Format::from_code(...).ok()?` and
`rowkey::canonical(...).ok()`, discarding the error. Every failure — NULL row key, non-UTF-8
text, wrong-width binary integer, unknown format code — collapses to `None`, and a `DBS3` value
then surfaces as `RowKeyMissing`, whose refusal tells the client to "select the table's row
key". The client already selected it.

**Why it matters**: `canonical`'s own doc says "Callers turn that into a refusal rather than
binding the empty string" — the read path turns it into a *different* refusal that misdirects
the fix. The write path keeps the error typed; the two directions disagree about how much of
the diagnosis to keep.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 A canonicalisation failure on the read path is refused under its own error, distinguishable from a missing projection
- [x] #2 A test with a NULL row key in a projected row asserts the message names the NULL
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
The read path now keeps the row-key error typed. `decrypt_row` builds row keys through the new `read_row_key` helper into `Vec<Option<Result<RowKey, Error>>>`; `Format::from_code` and `rowkey::canonical` errors are no longer discarded with `.ok()`. `Error::RowKeyType` joined `is_refusal`, so a NULL / non-UTF-8 / wrong-width / unknown-format key is refused under its own message rather than surfacing as `RowKeyMissing`. The failure is deferred to the point where a value actually needs a key: a value that opens without one (pre-migration plaintext, a legacy `DBS2` envelope) is unaffected, so an outer joins unmatched row still relays. AC#2: `an_unusable_row_key_is_refused_as_itself_not_as_a_missing_projection` asserts the ErrorResponse names "row key is NULL", does not read as the missing-projection refusal, covers the wrong-width binary case, and pins that a genuinely unprojected key still reports itself. `an_unusable_row_key_does_not_refuse_a_value_that_needs_no_key` pins the non-regression.
<!-- SECTION:NOTES:END -->
