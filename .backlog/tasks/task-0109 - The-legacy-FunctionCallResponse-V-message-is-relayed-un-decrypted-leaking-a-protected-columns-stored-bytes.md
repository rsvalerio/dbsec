---
id: TASK-0109
title: >-
  The legacy FunctionCallResponse (V) message is relayed un-decrypted, leaking a
  protected column's stored bytes
status: Triage
assignee: []
created_date: '2026-08-14 18:16'
labels:
  - security-review
  - security
  - read-path
dependencies: []
modified_files:
  - crates/proxy/src/rows.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/rows.rs:286` (decryptor `inspect` message-type dispatch).

**What**: the decryptor's `inspect` matches only `'T' 'n' 'D' 'C' 'I' 's' 'E' 'Z'`; every other message type falls to `_ => Ok(None)` and is relayed verbatim. The legacy fast-path (`FunctionCall` `'F'` → `FunctionCallResponse` `'V'`) bypasses SQL entirely, so the rewriter never sees it and the decryptor relays `'V'` through the `_` arm.

**Why it matters**: a function invoked over the fast-path that surfaces a protected column's stored bytes (`lo_get`, a custom accessor, a `SECURITY DEFINER` reader) returns them to the client in stored form — `blind_index || envelope` ciphertext for encrypted columns, or the unmasked stored value for a mask-only column. The leak is ciphertext for encrypted columns (fail-safe-ish) but is a genuine read-path completeness gap in the "function results" category, and it escapes `reject` because the frame never reaches a refusal site. Obscure (the fast-path is rarely used by modern drivers) hence low, but real.

**Fix shape**: decide the fast-path policy explicitly — either treat `'V'` as an `on_unprotected`/read-refusal site (warn/refuse, since the proxy cannot know which column the result came from), or document the fast-path as unsupported and refuse `FunctionCall` `'F'` outright. Silent relay through the `_` arm should not be the default.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 `FunctionCallResponse` ('V') is no longer silently relayed through the catch-all arm
- [ ] #2 The fast-path is either refused or its results are subject to the read-path refusal policy
- [ ] #3 The chosen behaviour is documented alongside the COPY caveat
<!-- AC:END -->
