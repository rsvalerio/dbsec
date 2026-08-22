---
id: TASK-0277
title: >-
  SEC-31: text_plaintext implements only the hex half of bytea input, so
  escape-format literals and malformed \x seal bytes the server would never have
  stored
status: Triage
assignee: []
created_date: '2026-08-22 00:45'
labels:
  - code-review-rust
  - security
dependencies: []
modified_files:
  - crates/proxy/src/encrypt/mod.rs
  - crates/proxy/src/encrypt/seal.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/encrypt/mod.rs:525`

**What**: text_plaintext (mod.rs:525-535) for WireForm::Bytea decodes a `\x…` prefix with hex::decode and otherwise seals the literal's own characters. PostgreSQL's bytea input also accepts the escape format — `'\\'` is one backslash, `'\000'` is byte 0 — and permits whitespace between hex digit pairs (`'\x61 62'`). For a bytea-form protected column, `INSERT … VALUES ('C:\\tmp')` is sealed as the 7 bytes `C:\\tmp` where the server would store `C:\tmp`; `'\x61 62'` fails hex::decode and is silently sealed as the literal text `\x61 62` (an odd-length or non-hex `\x…` likewise falls back to the text instead of the error the server would raise). literal_plaintext (seal.rs:638) and the search-index path (predicate.rs index_value / rewrite_in_list) inherit the same decoding, so the blind index is computed over the wrong bytes too.

**Why it matters**: Silent divergence between what the client wrote and what is sealed: the value read back differs from what an unproxied server would have stored, and an equality search over the same literal indexes the wrong plaintext. No Unprotected site fires because the literal is 'recognised'.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 text_plaintext for WireForm::Bytea decodes the escape format (`\\`, `\ooo`) and hex with interior whitespace exactly as PostgreSQL's byteain does
- [ ] #2 A `\x` literal that is not valid hex is reported as Unprotected::UnsupportedValue (or refused) rather than sealed as its own text
- [ ] #3 Unit tests for escape-format, whitespace-separated hex and malformed hex on both the seal and the blind-index paths
<!-- AC:END -->
