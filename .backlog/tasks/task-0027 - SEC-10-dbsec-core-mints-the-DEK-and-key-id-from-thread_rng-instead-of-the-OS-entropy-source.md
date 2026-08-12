---
id: TASK-0027
title: >-
  SEC-10: dbsec-core mints the DEK and key id from thread_rng instead of the OS
  entropy source
status: Done
assignee:
  - TASK-0053
created_date: '2026-08-11 19:24'
updated_date: '2026-08-12 16:51'
labels:
  - code-review-rust
  - security
  - crypto
dependencies: []
modified_files:
  - crates/core/src/keys.rs
  - crates/core/src/envelope.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/core/src/keys.rs:82`, `crates/core/src/keys.rs:84`

**What**: `FileKeySource::generate` draws both the key id and the 32-byte data encryption key from the thread-local RNG:

```rust
rand::thread_rng().fill_bytes(&mut id);
rand::thread_rng().fill_bytes(key.as_mut());
```

This is the same finding as TASK-0011, which is scoped to `crates/proxy/src/vault.rs`. It is filed separately because it lives in a different crate and file, so a fix to `vault.rs` will not touch it and `--modified-file` scoping would miss it. The two should probably land together.

**Why it matters**: `ThreadRng` on `rand` 0.8 is CSPRNG-backed (ChaCha12, reseeded from the OS), so nothing is broken today — this is hardening and auditability. The reasons still apply: a userspace generator state sits between the OS and a long-lived key, that state is what survives `fork()` into a child process, and an auditor tracing "where does the master key come from" has to reason about reseeding policy instead of reading one line. On `rand` 0.8 the drop-in is `rand::rngs::OsRng`, which implements `RngCore` and works at both callsites unchanged.

`envelope.rs:31` also uses `thread_rng()` for the GCM nonce. That one is defensible — a nonce is not key material and needs unpredictability rather than long-term secrecy — but if the crate adopts a single rule for cryptographic randomness it is simpler to apply it there too than to leave one exception that a future reader has to re-derive.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 FileKeySource::generate draws the key id and DEK from OsRng (or getrandom) rather than thread_rng
- [x] #2 The GCM nonce draw in envelope.rs either uses the same source or carries a comment explaining why thread_rng is sufficient for a nonce
- [x] #3 A grep for thread_rng across crates/core non-test code returns nothing, or each remaining use is a documented non-cryptographic one
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
AC #2 satisfied by the comment route rather than by switching the source: `envelope.rs`'s GCM nonce keeps `rand::thread_rng()` and now carries a comment saying why. A nonce is not key material — it is public and stored in the clear in the envelope header, and what it needs is unpredictability and non-repetition, not long-term secrecy. It is also drawn once per protected value on the data path, where `OsRng`'s `getrandom` syscall would cost several times the AES work it accompanies; repetition is bounded separately by `MAX_ENCRYPTIONS_PER_KEY`.

AC #3 therefore reads as its second clause: the one remaining `thread_rng` in crates/core non-test code is that nonce draw, and it is documented in place as the deliberate exception. Every key-material draw (`FileKeySource::generate`'s key id and DEK) now uses `rand::rngs::OsRng::try_fill_bytes`, with a new `Error::Entropy` variant so a refusing entropy source is an error rather than `OsRng`'s panic.
<!-- SECTION:NOTES:END -->
