---
id: TASK-0011
title: >-
  SEC-10: cryptographic key material is generated from thread_rng instead of the
  OS entropy source
status: Done
assignee:
  - TASK-0053
created_date: '2026-08-11 19:13'
updated_date: '2026-08-12 16:51'
labels:
  - code-review-rust
  - security
  - vault
dependencies: []
modified_files:
  - crates/proxy/src/vault.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/vault.rs:71`, `crates/proxy/src/vault.rs:136`

**What**: Both places that generate key material use the thread-local RNG:

- line 71 — `rand::thread_rng().fill_bytes(&mut key_id);` mints the 16-byte key id stamped into every ciphertext envelope.
- line 136 — `rand::thread_rng().fill_bytes(fresh.as_mut());` mints the 32-byte deterministic index key, which is the HMAC key behind blind indexes, FPE tweaks, and tokens.

SEC-10 asks for the OS entropy RNG for key generation and security tokens. On `rand` 0.8 (the workspace pin, root `Cargo.toml`) that is `rand::rngs::OsRng`, which implements `RngCore` and is a drop-in for both callsites.

**Why it matters**: `ThreadRng` is CSPRNG-backed (ChaCha12, reseeded from the OS), so this is not a break today — it is a hardening and auditability finding rather than an exploitable one. The reasons to change it anyway are concrete: `ThreadRng` interposes a userspace generator state between the OS and a long-lived key, which is exactly the state that survives `fork()` in a child process and the layer that reseeding bugs live in; and a reviewer auditing "where does key material come from" has to reason about `ThreadRng`'s reseeding policy instead of reading one line. Line 136 in particular mints a key that by design can never rotate, so it is the single highest-consequence random draw in the crate. `OsRng` costs nothing here — both calls happen once per process or once per column name.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Both key-material draws use rand::rngs::OsRng (or getrandom directly) rather than thread_rng
- [x] #2 A grep for thread_rng in non-test crate code returns nothing, or each remaining use is a documented non-cryptographic one
<!-- AC:END -->
