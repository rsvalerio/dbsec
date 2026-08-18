---
id: TASK-0102
title: >-
  A malformed Vault addr panics via vaultrs Url::parse().unwrap() instead of
  erroring cleanly
status: Done
assignee:
  - TASK-0119
created_date: '2026-08-14 14:06'
updated_date: '2026-08-18 09:32'
labels:
  - security-review
  - reliability
  - vault
dependencies: []
modified_files:
  - crates/proxy/src/config.rs
  - crates/proxy/src/vault.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/vault.rs:304` passes `config.addr` straight to vaultrs; `Config::validate` never parses it as a URL.

**What**: vaultrs's `VaultClientSettingsBuilder::address()` does `Url::parse(...).unwrap()` (documented "# Panics"). A malformed `addr` (e.g. the literal `"a"` the config tests use) passes validation and then panics inside `VaultKeySource::connect` instead of returning the clean startup error every neighboring failure gets. Verified against the locked vaultrs 0.7.4 source.

**Why it matters**: a config typo becomes a startup panic rather than a diagnosable error, bypassing the crate's no-panic error discipline. Availability/robustness only.

**Fix shape**: validate `[vault] addr` as a URL in `Config::validate` (and reject non-http(s) schemes per the related insecure-addr finding), so a bad addr is a clean error.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 A malformed vault addr is rejected at config validation with a clean error
- [x] #2 A test covers a malformed vault addr
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Fixed in TASK-0119 (branch code-review/TASK-0119). `VaultConfig::validate_addr` parses `[vault] addr` with `url::Url::parse` during `Config::validate`, so a malformed address is a clean `Error::InvalidConfig` at startup rather than a `Url::parse().unwrap()` panic inside `VaultClientSettingsBuilder::address` on the async connect path. `url` is pinned in the workspace at the same major version vaultrs itself resolves, so the two agree on what a valid address is by construction.

Defence in depth: `vault::client_settings` parses the address again before handing it to vaultrs, so the panic stays unreachable even if a future caller reaches the connect path without going through validation.

Tests: `config::tests::a_malformed_vault_addr_is_a_startup_error` (the literal `"a"` the config tests used to carry, `https://[`, the empty string, a scheme-less `host:port`, and a `file://` URL) and `vault::tests::a_malformed_vault_addr_is_an_error_rather_than_a_panic`.
<!-- SECTION:NOTES:END -->
