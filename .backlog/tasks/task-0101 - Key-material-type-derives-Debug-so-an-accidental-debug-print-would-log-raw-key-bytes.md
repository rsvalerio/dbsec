---
id: TASK-0101
title: >-
  Key material type derives Debug, so an accidental debug-print would log raw
  key bytes
status: Done
assignee:
  - TASK-0118
created_date: '2026-08-14 14:06'
updated_date: '2026-08-17 20:38'
labels:
  - security-review
  - security
  - crypto
dependencies: []
modified_files:
  - crates/core/src/keys.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/core/src/keys.rs:14` (`Key = Zeroizing<[u8; 32]>`).

**What**: `zeroize::Zeroizing` derives `Debug`, so `Key` prints its raw bytes if ever Debug-formatted. No production site does today (verified), but any future `?key` in a `tracing` call, or a `#[derive(Debug)]` on a struct that holds a `Key`, compiles silently and logs raw key material.

**Why it matters**: latent key-logging footgun in a codebase that otherwise hand-writes redacting `Debug` for secret-bearing types (`Secret`, `IndexKeyRecord`, `TlsContext`).

**Fix shape**: wrap key material in a newtype with a redacting `Debug` (the treatment secret types already get), so an accidental debug-print cannot compile to a raw-bytes log.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Key material cannot be Debug-formatted into its raw bytes
- [x] #2 A struct holding a Key can derive Debug without exposing key material
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Fixed in wave TASK-0118. `keys::Key` is now a newtype over `Zeroizing<[u8; 32]>` instead of an alias for it, with a hand-written `Debug` that prints `Key(<redacted>)` — the same treatment `Secret`, `IndexKeyRecord` and `TlsContext` already get. `Deref<Target = [u8; 32]>`, `AsRef<[u8]>`, `Key::new` and `From<Zeroizing<[u8; 32]>>` keep every existing use site working unchanged (`*key`, `key.as_ref()`, deref coercion into `blind_index::compute` and `Cipher::with_budget`), so the redaction covers formatting only, not access.

AC #1 is pinned by `keys::tests::debugging_a_key_never_prints_its_bytes`; AC #2 by `keys::tests::a_struct_holding_a_key_can_derive_debug_safely`, which derives `Debug` on a struct holding a `Key` and asserts the non-secret field still prints while the key bytes do not.

Side effect cleaned up in-wave: the `zeroize` dependency in `fuzz/Cargo.toml` had no remaining user once the fuzz target's key source switched to `Key::new`, so it was removed (`cargo check` in fuzz/ still passes).
<!-- SECTION:NOTES:END -->
