---
id: TASK-0133
title: >-
  The GHASH authentication subkey inside Aes256Gcm is still left in freed heap
  when a Cipher drops
status: Done
assignee:
  - TASK-0141
created_date: '2026-08-17 20:44'
updated_date: '2026-08-18 10:26'
labels:
  - code-review-rust
  - security
  - crypto
dependencies: []
modified_files:
  - Cargo.toml
  - crates/core/src/envelope.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/core/src/envelope.rs:129` (`Cipher` holds `Aes256Gcm`), workspace `Cargo.toml:23` (where `aes/zeroize` is enabled)

**What**: TASK-0093 enabled `aes`'s `zeroize` feature, so the expanded AES round-key schedule inside `Aes256Gcm` is now wiped on drop. `Aes256Gcm` is `AesGcm<Aes256, U12>` and holds a *second* piece of key-derived state alongside the cipher: `ghash: GHash`, built from `H = E_K(0^128)`. `ghash` 0.5 and `polyval` 0.6 each wipe their copies of `H` only when their own optional `zeroize` features are on, and neither is enabled — verified against the vendored sources: `ghash::GHash::new_with_init_block` zeroizes its `h`/`h_polyval` locals under `#[cfg(feature = "zeroize")]`, and `polyval`'s backend implements the wipe under its own feature. `ghash`'s `zeroize` feature does **not** forward to `polyval`, so both would have to be turned on.

Neither crate is a direct dependency, so enabling the features means adding `ghash` and `polyval` to the workspace manifest purely for Cargo feature unification — two direct dependencies nothing in the tree calls, version-coupled to whatever `aes-gcm` 0.10 pins. That trade is a judgement call, which is why it was not taken as a drive-by.

**Why it matters**: when a DEK rolls after exhausting its budget, the old `Cipher` drops and `H` is freed intact. `H` is not the DEK — it does not decrypt anything — but it is the GHASH authentication subkey, so recovering it from a later heap disclosure (core dump, swap, cold boot) gives tag-forgery capability for every ciphertext under that DEK. Smaller than the key-schedule exposure that TASK-0093 closed, and the same class: state derived from the key, surviving the wipe of the key itself, in a crate that is otherwise rigorous about this.

**Origin**: discovered during TASK-0118 while fixing TASK-0093 (whose acceptance criteria are about the AES round-key schedule specifically, and are met).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 The GHASH subkey derived from a DEK is wiped when the Cipher holding it drops, or the decision not to add ghash/polyval as direct dependencies is recorded next to the aes zeroize note
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Implemented in wave TASK-0141 (branch code-review/TASK-0141). AC #1 satisfied via its
second branch: the decision not to add ghash/polyval is recorded next to the aes zeroize
note in the workspace Cargo.toml, and in the envelope module docs.

The decision is *not* the cost/benefit judgement the task assumed ("two unused direct
dependencies for a wipe"). Verified against ghash 0.5.1 and polyval 0.6.2 — the versions
aes-gcm 0.10.3 resolves — enabling those features **would not wipe H at all** on any
platform dbsec ships on:

- aes-gcm 0.10.3 `AesGcm` holds `ghash: GHash` (src/lib.rs:201), built at :237, for the
  life of the cipher. `AesGcm` has no `Drop` impl.
- `ghash::GHash(Polyval)`. Its `zeroize` feature wipes only two *construction-time
  locals* in `GHash::new_with_init_block` (`h` at lib.rs:74-75, `h_polyval` at :80-81).
  It does not forward to polyval — ghash's only feature forwarding is `std =
  ["polyval/std"]`.
- polyval's `zeroize` feature adds `impl Drop` to `backend::soft` (soft64.rs:96-102,
  soft32.rs:117-122) and `backend::clmul` (clmul.rs:143-150). On x86/x86_64 and aarch64,
  `polyval::Polyval` is `backend::autodetect::Polyval` (backend.rs cfg_if), which stores
  the backend in a `union Inner { intrinsics: ManuallyDrop<..>, soft: ManuallyDrop<..> }`.
  A union never runs drop glue on its fields, and `autodetect::Polyval` has no `Drop` of
  its own even under the feature — so those backend destructors are unreachable.
- The aarch64 `pmull` backend has no zeroize Drop at all; it is a commented-out TODO
  (pmull.rs:192-198).

So the only builds where the feature would bite are `--cfg polyval_force_soft` ones,
which give up hardware GHASH on the data path to wipe 16 bytes. Not taken.

Upstream would have to give `autodetect::Polyval` a `Drop` that dispatches on the
CPU-feature token, and fill in the pmull TODO. The Cargo.toml comment says to revisit if
that lands; it sits directly above the `aes-gcm = "0.10"` line, which is what a future
version bump touches.

Residual exposure recorded in the envelope module docs under "What a dropped `Cipher`
leaves behind", including why it matters (knowing H lets an attacker forge tags for
ciphertexts under that DEK, since the E_K(J0) term cancels between two messages sharing a
nonce) and what narrows it today (crate::hardening: RLIMIT_CORE = 0, PR_SET_DUMPABLE = 0).

Also corrected in passing: the Cargo.toml comment named a test
`the_aes_key_schedule_is_wiped_on_drop` that does not exist; the test is
`the_aes_key_schedule_is_wiped_when_a_cipher_drops`.
<!-- SECTION:NOTES:END -->
