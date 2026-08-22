---
id: TASK-0238
title: >-
  ERR-2: block_on folds a Vault timeout and the current-thread-runtime refusal
  into CoreError::KeySource(String), so a slow Vault is indistinguishable from a
  corrupt stored key at the relay's error site
status: Triage
assignee: []
created_date: '2026-08-21 19:50'
labels:
  - code-review-rust
  - error-handling
dependencies: []
modified_files:
  - crates/vault/src/source.rs
  - crates/core/src/lib.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/vault/src/source.rs:594` (also `crates/vault/src/source.rs:601`, `crates/vault/src/source.rs:1206`)

**What**: `VaultKeySource::block_on` produces two distinct failures — "VaultKeySource needs a multi-thread tokio runtime" (a deployment bug, permanent) and "vault did not answer within {timeout}" (transient, retryable, and the signal an operator wants alerted on separately) — and both are `CoreError::KeySource(format!(..))`, the same variant `decode_key_hex` uses for "stored index key must be 32 bytes" and `IndexKeyRecord::current_key` uses for a record naming a missing version. The relay logs whatever `KeySource` returns at ERROR and fails the session; nothing upstream can tell a timeout from data corruption except by substring-matching the message, and the in-crate test does exactly that (`error.to_string().contains("fetching DEK")`). TASK-0059 (Done) gave the *vaultrs* failures a typed `KeyBackend { source }`; the timeout, which the crate itself raises, was left as a string.

**Why it matters**: ERR-2 / ERR-10 — domain errors callers react to differently need variants, and "backend unreachable/slow" versus "stored material is invalid" is the one distinction a key source's caller most needs (retry and page on the first, stop and investigate the second). `tokio::time::error::Elapsed` implements `std::error::Error`, so even without a new core variant the timeout can go through `backend_error(context, elapsed)` today and stay reachable via `source()`; a dedicated `CoreError::KeyBackendTimeout { what, after }` (in `crates/core/src/lib.rs`) is the cleaner end state.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A Vault lookup timeout is reported through a variant (or a KeyBackend source of type Elapsed) that a caller can match without parsing the message
- [ ] #2 The current-thread-runtime refusal is distinguishable from a data error (its own variant or documented as a panic-class misuse)
- [ ] #3 The hung-Vault test matches on the variant/source rather than a message substring
<!-- AC:END -->
