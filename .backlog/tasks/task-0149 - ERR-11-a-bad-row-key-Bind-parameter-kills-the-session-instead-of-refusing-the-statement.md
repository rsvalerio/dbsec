---
id: TASK-0149
title: >-
  ERR-11: a bad row-key Bind parameter kills the session instead of refusing the
  statement
status: Done
assignee:
  - TASK-0174
created_date: '2026-08-19 08:27'
updated_date: '2026-08-19 09:55'
labels:
  - code-review-rust
  - error-handling
dependencies: []
modified_files:
  - crates/proxy/src/encrypt/mod.rs
  - crates/proxy/src/rowkey.rs
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/encrypt/mod.rs:538`

**What**: resolving `RowKeySource::Param` in `QueryRewriter::bind` propagates with `?`:

```rust
let format = rowkey::Format::from_code(bind.param_format(*index))?;
Some(rowkey::canonical(*type_oid, format, raw)?)
```

`rowkey::canonical` returns `Error::RowKeyType` for a NULL row key, for non-UTF-8 text, and
for a binary integer of the wrong width. `bind` returns `Result<FrameAction, Error>`, so any
of those closes the connection with no ErrorResponse. `UPDATE users SET ssn = $1 WHERE
id = $2` with `$2` bound NULL is ordinary, well-formed client traffic.

**Why it matters**: this is the exact regression `record_param` was written to remove, two
lines away in the same function — "it used to travel as `Rejection::Fatal`, which tore the
session down over well-formed SQL and told the client nothing but a closed socket, and under
a connection pool the retry killed the next connection too". The row-key work added a new
client-input error at the same Bind site without routing it through the statement-level
refusal path.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Error::RowKeyType and Format::from_code failures raised while resolving a Bind row key become Rejection::Refused, not Err
- [x] #2 The refusal message names the placeholder and the row-key column
- [x] #3 A test binds NULL to the row-key parameter and asserts an ErrorResponse followed by a usable session
<!-- AC:END -->
