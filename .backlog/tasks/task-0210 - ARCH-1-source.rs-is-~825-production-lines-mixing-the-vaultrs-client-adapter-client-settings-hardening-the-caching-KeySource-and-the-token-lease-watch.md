---
id: TASK-0210
title: >-
  ARCH-1: source.rs is ~825 production lines mixing the vaultrs client adapter,
  client-settings hardening, the caching KeySource, and the token-lease watch
status: Triage
assignee: []
created_date: '2026-08-21 19:36'
labels:
  - code-review-rust
  - architecture
dependencies: []
modified_files:
  - crates/vault/src/source.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/vault/src/source.rs:1`

**What**: Outside its test module the file holds four separable concerns: (1) the `KeyStore` trait plus the `VaultStore` adapter over `vaultrs` KV v2/Transit with its error classifiers (`is_not_found`, `is_cas_conflict`, `backend_error`); (2) `client_settings` and the `VAULT_SKIP_VERIFY` hardening; (3) `VaultKeySource` with its three caches, `block_on` bridge, and the index-key mint/migrate logic; (4) `TokenStatus`/`TokenCheck`/`check_token`/`token_watch`. The module doc is ~75 lines because it has to introduce all of them.

**Why it matters**: ARCH-1's >500-line / mixed-concerns threshold. The test module already shows the seams (store fakes vs settings vs token tests). Splitting into e.g. `store.rs`, `settings.rs`, `source.rs`, `token.rs` under `vault/src/` lets each file carry its own docs and makes the `#[doc(hidden)]` testing seams easier to keep out of the public surface.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The vaultrs adapter (KeyStore + VaultStore + error classifiers), client settings, the key source, and the token watch live in separate modules
- [ ] #2 Public API (VaultKeySource, VaultStore, token_watch, re-exports) is unchanged; cargo doc and cargo test -p dbsec-vault pass
<!-- AC:END -->
