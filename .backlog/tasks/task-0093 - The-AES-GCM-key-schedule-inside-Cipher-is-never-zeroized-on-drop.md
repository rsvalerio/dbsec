---
id: TASK-0093
title: The AES-GCM key schedule inside Cipher is never zeroized on drop
status: Triage
assignee: []
created_date: '2026-08-14 14:06'
labels:
  - security-review
  - crypto
dependencies: []
modified_files:
  - crates/core/src/envelope.rs
  - Cargo.toml
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/core/src/envelope.rs:52-58` (`Cipher` holds `Aes256Gcm`); workspace `Cargo.toml:23-24` pulls `aes`/`aes-gcm` without the `zeroize` feature.

**What**: the raw 32-byte DEK is `Zeroizing`, but the expanded AES-256 round-key schedule that `Aes256Gcm::new` derives is stored in a plain allocation with no `Drop`/`Zeroize`. Confirmed via Cargo.lock: neither `aes 0.8` nor `aes-gcm 0.10` pulls `zeroize` and the feature is not enabled. The original key is recoverable from the round keys.

**Why it matters**: when a DEK rolls after exhausting its budget (`Ciphers::roll_active` replaces the active `Arc<Cipher>`), the old `Cipher` drops and leaves the full key schedule in freed heap; a later heap disclosure (core dump, swap, cold-boot) recovers the DEK long after the `Zeroizing` key bytes were wiped. Inconsistent with the crate's otherwise-rigorous zeroize posture (it hand-rolls hex in keys.rs to avoid stray key copies).

**Fix shape**: enable the `zeroize` feature on `aes-gcm`, or otherwise bound the key schedule's lifetime so it is wiped on drop.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The expanded AES round-key schedule is wiped when a Cipher is dropped
- [ ] #2 A DEK rolling to a fresh key leaves no recoverable key schedule in freed memory
<!-- AC:END -->
