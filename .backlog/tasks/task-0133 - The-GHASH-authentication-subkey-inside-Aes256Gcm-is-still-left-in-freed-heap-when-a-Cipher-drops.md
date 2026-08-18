---
id: TASK-0133
title: >-
  The GHASH authentication subkey inside Aes256Gcm is still left in freed heap
  when a Cipher drops
status: Triage
assignee: []
created_date: '2026-08-17 20:44'
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
- [ ] #1 The GHASH subkey derived from a DEK is wiped when the Cipher holding it drops, or the decision not to add ghash/polyval as direct dependencies is recorded next to the aes zeroize note
<!-- AC:END -->
