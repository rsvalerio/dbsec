---
id: TASK-0094
title: Vault DEK base64 plaintext and the legacy index-key map are left un-zeroized
status: Triage
assignee: []
created_date: '2026-08-14 14:06'
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
- [ ] #1 Locally-owned DEK base64 plaintext is held in a zeroizing buffer
- [ ] #2 The legacy shared-map index keys are wiped before the map drops
<!-- AC:END -->
