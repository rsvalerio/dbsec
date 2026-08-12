---
id: TASK-0031
title: 'ERR-2: envelope::encrypt reports an encryption failure as Error::Decrypt'
status: Done
assignee:
  - TASK-0054
created_date: '2026-08-11 19:25'
updated_date: '2026-08-12 11:02'
labels:
  - code-review-rust
  - errors
dependencies: []
modified_files:
  - crates/core/src/envelope.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/core/src/envelope.rs:33-35`

**What**: The encrypt path maps its AEAD failure onto the decrypt error variant:

```rust
let ciphertext = cipher
    .encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext, aad: key_id })
    .map_err(|_| Error::Decrypt)?;
```

`Error::Decrypt` renders as `"decryption failed (wrong key or tampered data)"`. Neither half of that message is true on this path — there is no wrong key (it was just handed over by the `KeySource`) and no tampering (the plaintext came from the client).

**Why it matters**: This is unreachable in practice — `aes-gcm`'s `encrypt` only fails when the plaintext exceeds the GCM length limit of roughly 64 GiB, which `MAX_MESSAGE_LEN` (1 GiB) already precludes — so it is a diagnostics bug rather than a live one. That is precisely why it deserves a cheap fix rather than a careful one: if it ever does fire, an operator gets a message pointing at tampered data and a wrong key while looking at a write. The lie costs a debugging session, and the error would be reported against the read path.

Two options, either acceptable: add a distinct `Error::Encrypt` variant, or — since the condition is a violated internal invariant rather than an expected failure (ERR-11) — replace the `map_err` with an `.expect()` whose message names the actual precondition, e.g. `"AES-GCM encrypt only fails past the 64 GiB plaintext limit, which MAX_MESSAGE_LEN precludes"`. The second option documents the reasoning at the point where a future reader needs it.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 The encrypt path no longer returns Error::Decrypt; it either has its own variant or documents the invariant that makes the branch unreachable
- [x] #2 The reasoning about the GCM plaintext length limit versus MAX_MESSAGE_LEN is recorded at the callsite
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
The encrypt path now maps its AEAD failure to a new `Error::Encrypt` variant
instead of `Error::Decrypt`. A distinct variant was chosen over `.expect()`
because the plaintext arrives from a client: a panic on a reachable-looking
write path would be a DoS if the invariant were ever wrong, while an error keeps
the fail-closed posture.

The reasoning is recorded at the callsite in `Cipher::encrypt`: AES-GCM
encryption fails only past the ~64 GiB plaintext limit, which
`pgwire::MAX_MESSAGE_LEN` (1 GiB) already precludes, so the branch is a violated
internal invariant rather than a wrong key or tampering.
<!-- SECTION:NOTES:END -->
