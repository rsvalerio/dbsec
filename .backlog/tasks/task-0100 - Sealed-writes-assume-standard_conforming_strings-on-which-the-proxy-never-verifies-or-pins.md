---
id: TASK-0100
title: >-
  Sealed writes assume standard_conforming_strings = on, which the proxy never
  verifies or pins
status: To Do
assignee:
  - TASK-0122
created_date: '2026-08-14 14:06'
updated_date: '2026-08-17 20:04'
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
- [ ] #1 Sealed bytea literals are robust to standard_conforming_strings being off, or the proxy pins/refuses the change
- [ ] #2 A test covers a session that sets standard_conforming_strings off before a protected write
<!-- AC:END -->
