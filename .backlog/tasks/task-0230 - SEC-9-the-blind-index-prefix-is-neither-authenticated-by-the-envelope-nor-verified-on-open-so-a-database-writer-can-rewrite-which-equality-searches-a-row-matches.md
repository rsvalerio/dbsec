---
id: TASK-0230
title: >-
  SEC-9: the blind index prefix is neither authenticated by the envelope nor
  verified on open, so a database writer can rewrite which equality searches a
  row matches
status: Triage
assignee: []
created_date: '2026-08-21 19:50'
labels:
  - code-review-rust
  - security
dependencies: []
modified_files:
  - crates/core/src/transform.rs
  - crates/core/src/blind_index.rs
  - crates/core/src/envelope.rs
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/core/src/transform.rs:160-189` (also `crates/core/src/blind_index.rs:23-36`, `crates/core/src/envelope.rs:163-171`)

**What**: A searchable column stores `hmac(index_key, plaintext) || envelope` (`blind_index::prepend`). The 32-byte index is not part of the AES-GCM associated data — `CellContext::aad` / `aad_with_row` cover only the key id, the cell context and the row key — and `EncryptTransform::open` splits the prefix off (`Some((_index, enveloped)) => enveloped`) and never compares it against `blind_index::compute(key, plaintext)` after decrypting. Nothing on either path therefore notices when the 32-byte prefix has been replaced.

The threat model in `lib.rs` names the database — its DBA, an at-rest compromise, an injected `UPDATE` — as the adversary, and the envelope AAD work (DBS2/DBS3) exists precisely so that adversary cannot move stored bytes around undetected. The index prefix is the one component of the stored form it can still edit freely: copy the prefix of a row known to hold `alice@example.com` onto any other row's envelope, and `WHERE substring(email from 1 for 32) = $1` now returns that row for Alice's address (or stops returning Alice's real row if her prefix is overwritten), while every `open` succeeds with no tamper signal.

**Why it matters**: Equality search is the only query path over encrypted columns the crate offers, and its result set is controllable by the party the crate is defending against. The integrity guarantee the README attaches to "a ciphertext is bound to its column and its row" does not extend to *which search hits the row*. Two closures are possible without touching the stored format: recompute the index from the opened plaintext in `EncryptTransform::open` and return `Error::Decrypt` (or a dedicated variant) on mismatch — the index key is already in hand — or, for a format-level fix in the next major, bind the index into the AAD.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 EncryptTransform::open on a searchable column verifies the stored 32-byte prefix against blind_index::compute(index_key, plaintext) after decryption and refuses on mismatch with a distinguishable error
- [ ] #2 A test seals a searchable value, overwrites its prefix with another plaintext's index, and asserts that open refuses rather than returning the plaintext
- [ ] #3 The module docs for blind_index and envelope state whether the index is authenticated, and the compatibility section in lib.rs records whether the check changes any stored bytes (it should not)
<!-- AC:END -->
