---
id: TASK-0231
title: >-
  DUP-1: the wrapped-DEK KV path is assembled by hand in both connect and
  fetch_dek, and decode_key_b64 / decode_key_hex are the same function with a
  different decoder
status: Triage
assignee: []
created_date: '2026-08-21 19:50'
labels:
  - code-review-rust
  - duplication
dependencies: []
modified_files:
  - crates/vault/src/source.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/vault/src/source.rs:563` (also `crates/vault/src/source.rs:364`, `crates/vault/src/source.rs:805`, `crates/vault/src/source.rs:816`)

**What**:
- `connect` writes the DEK at `format!("{}/deks/{}", config.path, hex::encode(key_id))` and `VaultStore::fetch_dek` reads it from `format!("{}/deks/{}", self.config.path, id_hex)` — two hand-built copies of the layout the module docs describe, while the index-key layout has `index_key_path` / `legacy_index_keys_path` helpers. A change to the DEK layout (a per-transit-key prefix, a version segment) has to be found twice, and the write side is not covered by the `FakeStore` tests, so a divergence would only show up against a live Vault.
- `decode_key_b64` and `decode_key_hex` are line-for-line identical except for the decoder call and the two message strings: decode, `try_from` to `[u8; 32]`, `Key::new`, `raw.zeroize()`. The zeroize-on-both-paths discipline is the part that must not drift, and it is currently maintained in two places.

**Why it matters**: DUP-1 / DUP-5 — both are small, but each is a place where the security-relevant invariant (same path on write and read; raw bytes wiped whether the length check passes or fails) is enforced by copy rather than by one function. A `dek_path(config_path, id) -> String` helper and a `decode_key(raw: Result<Vec<u8>, E>, what: &str)` core shared by both decoders remove the duplication without changing behaviour.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 One function builds the wrapped-DEK KV path and both connect and fetch_dek call it
- [ ] #2 decode_key_b64 and decode_key_hex share one 32-byte/zeroize core; existing decode tests pass unchanged
<!-- AC:END -->
