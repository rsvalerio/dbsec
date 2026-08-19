---
id: TASK-0185
title: >-
  SEC-11: a self-join that projects the row key once still opens the second
  instance's rows against the first's key
status: Done
assignee: []
created_date: '2026-08-19 09:44'
updated_date: '2026-08-19 12:28'
labels:
  - code-review-rust
  - security
dependencies: []
modified_files:
  - crates/proxy/src/rows.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/rows.rs:220` (`Resolved::row_key_ref`)

**What**: TASK-0153 made a result set that projects a row-keyed table's key
*more than once* refuse with `Error::AmbiguousRowKey`. The complementary shape
is still wrong: `SELECT a.id, a.ssn, b.ssn FROM users a JOIN users b ON …`
projects the key exactly once, so `row_key_ref` resolves cleanly, and `b.ssn`
is then opened against `a.id`'s key. It fails closed as `Error::Decrypt`, which
kills the session with the signal a *relocated* value produces.

The reason it was not fixed in the same change: the only detectable difference
is that a protected `(table_oid, attnum)` appears more than once, and that is
also true of `SELECT ssn, ssn FROM users`, where both fields genuinely name the
same row and decrypt correctly today. Refusing on duplication alone would break
that legitimate query; RowDescription carries nothing that separates the two
cases. Deciding which way to err is the work.

**Why it matters**: same as TASK-0153 — a detection control that fires on
ordinary SQL, and a torn-down session rather than a client-visible refusal.

**Origin**: discovered during TASK-0176 while fixing TASK-0153.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 A self-join that projects a row-keyed table's key once and a protected column of that table more than once either decrypts each instance correctly or is refused with a client-visible error naming the table
- [x] #2 A single-instance query that projects the same protected column twice (SELECT ssn, ssn FROM users) still decrypts, and a test pins that it is not caught by the chosen rule
<!-- AC:END -->
