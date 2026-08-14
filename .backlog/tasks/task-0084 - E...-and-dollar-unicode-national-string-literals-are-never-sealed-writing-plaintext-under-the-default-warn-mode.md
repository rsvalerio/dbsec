---
id: TASK-0084
title: >-
  E'...' and dollar/unicode/national string literals are never sealed, writing
  plaintext under the default warn mode
status: Triage
assignee: []
created_date: '2026-08-14 14:06'
labels:
  - security-review
  - security
  - sql-rewrite
dependencies: []
modified_files:
  - crates/proxy/src/encrypt.rs
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/encrypt.rs:1518-1524` (`literal_plaintext`), gate at `:913-916` (`seal_expr`).

**What**: `literal_plaintext` recognizes only `Value::SingleQuotedString` and `Value::Number`. PostgreSQL escape strings `E'...'` (sqlparser `Value::EscapedStringLiteral`), dollar-quoted `$$...$$`, `U&'...'` and `N'...'` all parse to other AST variants, return `None`, and fall through to the `UnsupportedValue` gate. Verified against sqlparser 0.53 and the surrounding code.

**Why it matters**: under the **default** `on_unprotected = "warn"`, `INSERT INTO users (email) VALUES (E'o\'brien@x.com')` (or `$$alice$$`) is logged and forwarded verbatim; PostgreSQL decodes the escape and stores plaintext in the encrypted column. Many drivers emit `E'...'` automatically for any string containing a backslash or control character, so this is reachable without the client doing anything exotic. It is not on the README fail-open radar (which lists DDL/bulk shapes), and the plaintext-in-log test never drives an E-string. `reject` does refuse it, so this is fail-open-under-default, not an ungated bypass.

**Fix shape**: teach `literal_plaintext`/`text_plaintext` the remaining PG string-literal variants (their decoded content is already available) so they seal instead of falling through.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 E-string, dollar-quoted, unicode and national string literals assigned to a protected column are sealed
- [ ] #2 A regression test inserts an E-string into a protected column and asserts ciphertext at rest
- [ ] #3 The plaintext-in-log test is extended to cover an E-string value
<!-- AC:END -->
