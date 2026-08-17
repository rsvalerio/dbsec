---
id: TASK-0102
title: >-
  A malformed Vault addr panics via vaultrs Url::parse().unwrap() instead of
  erroring cleanly
status: To Do
assignee:
  - TASK-0119
created_date: '2026-08-14 14:06'
updated_date: '2026-08-17 20:04'
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
- [ ] #1 A malformed vault addr is rejected at config validation with a clean error
- [ ] #2 A test covers a malformed vault addr
<!-- AC:END -->
