---
id: TASK-0165
title: >-
  ERR-7: read-path row-key failures are reported to the client as the wrong
  problem
status: To Do
assignee:
  - TASK-0177
created_date: '2026-08-19 08:31'
updated_date: '2026-08-19 09:01'
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
- [ ] #1 A canonicalisation failure on the read path is refused under its own error, distinguishable from a missing projection
- [ ] #2 A test with a NULL row key in a projected row asserts the message names the NULL
<!-- AC:END -->
