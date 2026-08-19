---
id: TASK-0145
title: >-
  SEC-11: rowkey::canonical does not normalise text-format values, so the write
  and read paths disagree
status: Done
assignee:
  - TASK-0175
created_date: '2026-08-19 08:26'
updated_date: '2026-08-19 10:03'
labels:
  - code-review-rust
  - security
dependencies: []
modified_files:
  - crates/proxy/src/rowkey.rs
  - crates/proxy/src/encrypt/seal.rs
  - crates/proxy/src/encrypt/mod.rs
  - crates/proxy/src/rows.rs
  - crates/proxy/src/resolve.rs
  - README.md
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/rowkey.rs:87`

**What**: `canonical`'s first arm is `(_, Format::Text)`, which only validates UTF-8 and
copies the bytes, on the premise that "text format is already PostgreSQL's own output".
That holds on the **read** path. It is false on the **write** path, which feeds it a SQL
literal's raw source text and the client's own text-format Bind bytes. PostgreSQL accepts
many spellings it never emits:

- `int2/4/8`: `0042`, `+42`, `' 42 '` — server outputs `42`
- `uuid`: uppercase, braced, unhyphenated — server outputs lowercase hyphenated
- `bpchar`: `char(n)` is blank-padded by the server on output but not in the client's
  input, so `'abc'` seals against `abc` and reads back as `abc       `

Three further defects in the same function:

- The `(_, Format::Text)` arm matches **any** type OID, so an unsupported type silently
  passes through as raw bytes — contradicting the module header ("anything else is refused
  at startup ... never a silent fallback to raw bytes"). The guarding test
  `unsupported_types_are_named_not_guessed` only exercises the binary arm.
- `decrypt_row` canonicalises with the **wire's** `RowDescription` type OID, never checked
  against the resolved `ResolvedRowKey::type_oid`, so after an `ALTER COLUMN ... TYPE` the
  two paths canonicalise under different types with no check.
- A negative integer literal (`WHERE id = -1`) parses as `UnaryOp{Minus, Number}`, so
  `literal_plaintext` returns `None` and the value falls through to a silent cell-only seal.

**Why it matters**: silent data loss. The value seals, the statement commits, and the first
read fails with `Error::Decrypt` — which this codebase treats as tampering: the session is
killed with no ErrorResponse. Every such row is unrecoverable *and* a false tamper alarm,
which trains operators to ignore the one alarm the feature produces. `char(n)` primary keys
are an ordinary legacy schema.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 canonical normalises through the type in both formats: integers parse and re-render, uuid parses case/format-insensitively and re-renders canonically, a value that does not parse is Err(RowKeyType)
- [x] #2 bpchar is either removed from supported() and refused at resolution naming the column, or padded/trimmed consistently on both paths
- [x] #3 An unsupported type OID is refused in the Text arm too, and decrypt_row refuses when the wire type OID disagrees with the resolved one
- [x] #4 Negative integer literals canonicalise correctly or reach Unprotected::RowKeyMissing, never a silent cell-only seal
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Fixed in wave TASK-0175 (branch code-review/TASK-0175). `rowkey::canonical` now parses and re-renders through the column type in *both* wire formats: integers via `FromStr` on the trimmed text (so `0042`, `+42`, ` 42 ` all canonicalise to `42`), uuid case/brace/hyphen-insensitively to the lowercase hyphenated output form, and `text`/`varchar` as the one genuine pass-through. An unsupported type OID is now refused in the text arm too, not passed through as raw bytes. `bpchar` was removed from `supported()`, so `char(n)` is refused at resolution naming the column (its blank padding cannot be reconciled without `atttypmod`). `RowKeySlot` now carries the resolved type OID alongside the wire one and `read_row_key` refuses when they disagree, canonicalising through the resolved one. Negative and signed numeric literals are recognised in `literal_plaintext` (`UnaryOp{Minus|Plus, Number}`), so `WHERE id = -1` names its row instead of falling through to the cell-only path. README documents the `char(n)` exclusion and that a key binds by value, not spelling.
<!-- SECTION:NOTES:END -->
