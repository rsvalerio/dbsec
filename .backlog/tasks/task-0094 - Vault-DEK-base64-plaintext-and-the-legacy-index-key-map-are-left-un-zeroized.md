---
id: TASK-0094
title: Vault DEK base64 plaintext and the legacy index-key map are left un-zeroized
status: Done
assignee:
  - TASK-0118
created_date: '2026-08-14 14:06'
updated_date: '2026-08-17 20:27'
labels:
  - security-review
  - security
  - vault
dependencies: []
modified_files:
  - crates/proxy/src/vault.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/vault.rs:325-328` (`datakey.plaintext` at startup), `:243-252` (`unwrapped.plaintext` per DEK fetch), `:438-455` (`read_legacy_index_keys` map).

**What**: `decode_key_b64` zeroizes the decoded raw `Vec`, but the base64 `String`s holding DEK plaintext (locally owned in `connect`, and inside vaultrs response structs) drop unwiped, and the legacy shared-map index keys are returned as a `HashMap<String, String>` of hex key material that is dropped without zeroization. Contrast: `KeyFile::Drop` and `IndexKeyRecord::Drop` wipe the equivalent shapes elsewhere. Verified against source.

**Why it matters**: one more plaintext copy of every DEK, and hex of every (unrotatable) legacy index key, survives in freed heap for a later disclosure — same class as the AES-key-schedule and the documented best-effort edges, but these are copies the crate owns and can wipe.

**Fix shape**: wrap the locally-owned base64 DEK plaintext in `Zeroizing`, and zeroize the legacy index-key map before it drops.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Locally-owned DEK base64 plaintext is held in a zeroizing buffer
- [x] #2 The legacy shared-map index keys are wiped before the map drops
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Fixed in wave TASK-0118.

AC #1: both locally-owned base64 DEK plaintexts are now held in `Zeroizing` — the startup `datakey.plaintext` in `connect`, and `unwrapped.plaintext` in `fetch_dek`, which is moved out of the `vaultrs` response struct rather than borrowed so it is wiped here instead of freed with the struct. The copies still inside `vaultrs`' own buffers remain out of reach, which the module already documents as a best-effort edge.

AC #2: the legacy shared map is now `LegacyIndexKeys`, a newtype over the `HashMap<String, String>` with a `Drop` that zeroizes every hex key — the same treatment `KeyFile` and `IndexKeyRecord` already get. The `KeyStore` seam returns it, so the fake store in tests exercises the same type. `vault::tests::the_legacy_shared_map_is_wiped_rather_than_dropped_intact` pins the wipe (serde sees through the newtype, so the stored KV shape is unchanged).
<!-- SECTION:NOTES:END -->
