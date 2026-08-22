---
id: TASK-0205
title: >-
  SEC-5: the Vault token is held in three places after resolve —
  VaultSetup.token, VaultSetup.config.token, and VaultStore.config.token for the
  life of the process
status: Triage
assignee: []
created_date: '2026-08-21 19:36'
labels:
  - code-review-rust
  - security
dependencies: []
modified_files:
  - crates/vault/src/lib.rs
  - crates/vault/src/source.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/vault/src/lib.rs:217` (also `crates/vault/src/source.rs:295`, `crates/vault/src/source.rs:553`)

**What**: `VaultConfig::resolve` builds `VaultSetup { config: self.clone(), token }` — the clone carries `config.token: Option<Secret>` alongside the resolved `token`, so a static-token setup holds two live copies. `VaultKeySource::connect` then stores `VaultStore { client, config: config.clone() }`, a third copy that lives as long as the key source, even though `VaultStore` only ever reads `mount`, `path`, `transit_mount` and `transit_key` from it. `Secret` zeroizes on drop, so these are not leaked on free, but they extend the token's in-memory lifetime and footprint beyond the one copy `VaultClient` needs.

**Why it matters**: SEC-5 asks secret-bearing types to keep the number of live copies minimal; every extra resident copy is another place a core dump, a swap page or a future `Debug` derive on a containing struct can expose the credential that unwraps every DEK. The fix is structural and cheap: `VaultStore` should hold only the KV/Transit path fields it uses, and `VaultSetup` should either strip `token` from its `config` or not duplicate the config at all.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 VaultStore holds only the fields it uses (mount, path, transit_mount, transit_key), not a VaultConfig carrying token/token_file
- [ ] #2 VaultSetup does not carry a second copy of the token inside config (either config.token is None/removed after resolution, or VaultSetup holds the non-secret fields and the single resolved Secret)
- [ ] #3 A test asserts that after connect only one Secret copy is owned by the crate's own types (or the structural change is documented on VaultSetup)
<!-- AC:END -->
