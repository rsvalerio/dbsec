---
id: TASK-0100
title: >-
  Sealed writes assume standard_conforming_strings = on, which the proxy never
  verifies or pins
status: Done
assignee:
  - TASK-0122
created_date: '2026-08-14 14:06'
updated_date: '2026-08-18 09:34'
labels:
  - security-review
  - sql-rewrite
dependencies: []
modified_files:
  - crates/proxy/src/encrypt.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/encrypt.rs:918-922` (seal), `:1163` (index literal), `:1528-1536` (`text_plaintext`).

**What**: sealed bytea values and blind-index tokens are emitted as `'\x...'` single-quoted strings, which PostgreSQL reads as hex bytea input only when `standard_conforming_strings = on` (the default). A session that issues `SET standard_conforming_strings = off` is tracked nowhere (grep-verified). Verified against source.

**Why it matters**: with the setting off, PostgreSQL applies C-style backslash processing to `'\x...'` before the bytea cast, corrupting every sealed write and making every rewritten searchable predicate (`substring(col from 1 for 32) = '\x...'`) match nothing. Not a plaintext disclosure (it fails toward garbage ciphertext / empty results), but silent corruption analogous to the search_path assumption.

**Fix shape**: pin `standard_conforming_strings` (emit it, or refuse when a session turns it off), or emit bytea literals in a form that does not depend on it.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Sealed bytea literals are robust to standard_conforming_strings being off, or the proxy pins/refuses the change
- [x] #2 A test covers a session that sets standard_conforming_strings off before a protected write
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Fixed in wave TASK-0122 (branch code-review/TASK-0122). Sealed BYTEA values and blind-index tokens now go out as `E'\\x…' (bytea_literal), whose backslash handling does not depend on standard_conforming_strings, instead of the plain `'\x…' that only reads as hex input while the setting is on. Turning the setting off is additionally tracked as an on_unprotected site (Unprotected::EscapeStringsChanged), and once it is off any ordinary single-quoted literal carrying a backslash is reported (Unprotected::AmbiguousLiteral) rather than sealed on a guess, because the server and sqlparser no longer read it as the same bytes. Tests: sealed_bytea_literals_do_not_depend_on_standard_conforming_strings, turning_standard_conforming_strings_off_is_an_unprotected_site, a_write_after_standard_conforming_strings_off_is_still_sealed_readably, a_backslash_literal_after_the_setting_moved_is_reported_not_guessed_at, turning_standard_conforming_strings_on_is_not_reported.
<!-- SECTION:NOTES:END -->
