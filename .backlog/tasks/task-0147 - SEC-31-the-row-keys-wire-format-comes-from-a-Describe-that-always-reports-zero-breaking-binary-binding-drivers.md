---
id: TASK-0147
title: >-
  SEC-31: the row key's wire format comes from a Describe that always reports
  zero, breaking binary-binding drivers
status: Done
assignee:
  - TASK-0176
created_date: '2026-08-19 08:27'
updated_date: '2026-08-19 09:41'
labels:
  - code-review-rust
  - security
dependencies: []
modified_files:
  - crates/proxy/src/rows.rs
  - crates/proxy/src/portal.rs
  - crates/core/src/pgwire.rs
  - crates/proxy/src/rowkey.rs
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/rows.rs:222` (capture), `crates/proxy/src/rows.rs:747` (use)

**What**: `Resolved::row_key_slot` takes the `format` code from the RowDescription field and
`decrypt_row` canonicalises the row key with it. But for the **statement** variant of
Describe, the protocol specifies the format code "is not yet known and will always be
zero" — result formats are chosen at Bind. `describe_answered` then hands that `Described`
to every queued Execute of the statement id, and the same `Described` is reused across
portals that bound *different* result formats.

A driver that describes the statement and binds binary result formats (sqlx's normal shape)
therefore canonicalises an `int4` row key of `00 00 00 2a` as text — `from_utf8` succeeds on
those bytes — producing `RowKey(b"\0\0\0*")` instead of `b"42"`. The AAD mismatches,
`Cipher::decrypt` returns `Error::Decrypt`, which `is_refusal` does not cover, so the
session is torn down with no ErrorResponse.

`a_row_bound_value_opens_whichever_format_the_client_chose` builds its RowDescription with
the true format already in it — the Describe-**portal** shape — so the defect is unexercised.
No e2e test references `row_key` at all, so the driver matrix passing proves nothing here.

**Why it matters**: row binding plus a binary-format driver is a broken combination that
looks like data corruption to the client and kills the connection; under a pool the retry
kills the next one. Fail-closed, but it makes DBS3 unusable for a whole class of drivers.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 The result format used to canonicalise a row key comes from the Bind that produced the rows, not from a statement-level RowDescription
- [x] #2 A test drives Parse -> Describe(statement) -> Bind(result format = binary) -> Execute over a row-keyed table and asserts the value opens
- [x] #3 An e2e case writes through a text-binding driver and reads back through a binary-binding one on a row-bound table
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Fixed in wave TASK-0176 (branch code-review/TASK-0176).

The result format now comes from the Bind that created the portal, not from
the RowDescription: `pgwire::BindMessage::result_format_codes` decodes the
section the proxy used to relay untouched, `portal::ResultFormats` holds it
per portal and per queued Execute, and `RowSource::Portal` carries it to
`rows::decrypt_row`. `RowKeyRef::Slot` no longer stores a format code and
`Described::fields` no longer keeps one — a statement-level Describe reports
zero for every column, so it was never an authority. The simple protocol has
no Bind and is all text, which is `ResultFormats::default()`.

Tests: `rows::tests::a_row_bound_value_opens_in_the_format_the_bind_asked_for`
drives Parse -> Describe(statement) -> Bind(result format = binary/text) ->
Execute (AC 2), replacing the old test that built the true format into the
RowDescription and so never exercised the defect. `e2e.rs::
a_row_bound_value_written_in_text_reads_back_in_binary` writes through the
simple protocol and reads back through tokio-postgres' prepared, binary-binding
path against a row-keyed table (AC 3); confirmed it fails with `Closed` when
the format is forced back to zero.
<!-- SECTION:NOTES:END -->
