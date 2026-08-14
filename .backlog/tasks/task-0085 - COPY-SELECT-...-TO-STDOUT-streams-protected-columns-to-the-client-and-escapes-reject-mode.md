---
id: TASK-0085
title: >-
  COPY (SELECT ...) TO STDOUT streams protected columns to the client and
  escapes reject mode
status: Triage
assignee: []
created_date: '2026-08-14 14:06'
labels:
  - security-review
  - security
  - sql-rewrite
  - read-path
dependencies: []
modified_files:
  - crates/proxy/src/encrypt.rs
  - crates/proxy/src/rows.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/encrypt.rs:549-556` (COPY classifier), `crates/proxy/src/rows.rs:260-286` (read path relays CopyData).

**What**: the write-path COPY classifier inspects only `CopySource::Table`. A query-source COPY — `COPY (SELECT email FROM users) TO STDOUT` — is `CopySource::Query`, falls through to `Ok(false)`, and is neither flagged nor rewritten. The read path only decrypts `'D'` DataRow frames and relays `CopyOutResponse`/`CopyData`/`CopyDone` verbatim.

**Why it matters**: `COPY (SELECT <protected col> FROM t) TO STDOUT` streams the stored form to the client **even under `on_unprotected = "reject"`** — ciphertext for encrypted columns (fail-safe) but the **unmasked plaintext** for mask-only columns. The table-form `COPY t TO STDOUT` is at least flagged (refused under reject) and is a documented on_unprotected site; the query-source form escapes the strict setting the docs say refuses it. Verified against source.

**Fix shape**: classify `CopySource::Query` COPY-OUT as an on_unprotected site when its query touches a protected column (or decline to relay CopyData for it), so `reject` refuses it and `warn` warns.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A query-source COPY TO whose query references a protected column is refused under reject
- [ ] #2 Under warn the same statement emits an on_unprotected warning
- [ ] #3 A test drives COPY (SELECT protected FROM t) TO STDOUT in both modes
<!-- AC:END -->
