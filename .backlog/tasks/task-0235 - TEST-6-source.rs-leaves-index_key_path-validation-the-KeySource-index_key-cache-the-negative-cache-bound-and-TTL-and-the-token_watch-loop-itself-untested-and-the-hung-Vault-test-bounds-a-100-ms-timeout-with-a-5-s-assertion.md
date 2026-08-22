---
id: TASK-0235
title: >-
  TEST-6: source.rs leaves index_key_path validation, the KeySource::index_key
  cache, the negative-cache bound and TTL, and the token_watch loop itself
  untested, and the hung-Vault test bounds a 100 ms timeout with a 5 s assertion
status: Triage
assignee: []
created_date: '2026-08-21 19:50'
labels:
  - code-review-rust
  - tests
dependencies: []
modified_files:
  - crates/vault/src/source.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/vault/src/source.rs:826` (also `crates/vault/src/source.rs:304`, `crates/vault/src/source.rs:680`, `crates/vault/src/source.rs:745`, `crates/vault/src/source.rs:788`, `crates/vault/src/source.rs:1202`)

**What**: The test module is thorough on the mint/migrate/race logic and the token decision, but these production branches have no test:
- `VaultStore::index_key_path` refusals (empty, `/`, `.`, `..`) — the only guard between a policy column name and a Vault URL.
- `KeySource::index_key` as called through the trait: that a second call for the same name is served from `index_keys` without a second `read_index_key` (the DEK side has `fetched_dek_is_cached`; the index side only tests `resolve_index_key` directly).
- `remember_missing`: the `MISSING_DEK_CACHE_MAX` bound and the TTL expiry of a negative entry.
- `token_watch` (the loop): that it runs `check_token` once per `TOKEN_CHECK_INTERVAL` and returns when `shutdown` resolves — testable with `#[tokio::test(start_paused = true)]` and `tokio::time::advance` (TEST-13) against a `FakeStore` that counts `token_status` calls.
- `a_hung_vault_fails_the_lookup_instead_of_parking_the_worker` asserts `elapsed < 5s` for a source built with a 100 ms timeout; a regression that made the timeout 4 s would pass. Assert within a small multiple of the configured timeout.

**Why it matters**: TEST-6/TEST-8 — each untested branch here is an operational guarantee the module docs advertise (bounded negative cache, per-column cache, a watch that stops on shutdown), and TASK-0225/0226/0228 will change three of them; tests that pin the current contract first make those changes safe.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Tests cover index_key_path acceptance and each refusal
- [ ] #2 A test drives KeySource::index_key twice through a FakeStore and asserts one read_index_key call
- [ ] #3 A paused-time test drives token_watch through at least two intervals, asserts the token_status call count, and asserts it returns when shutdown resolves
- [ ] #4 The hung-Vault test asserts elapsed is within a small multiple of the configured 100 ms timeout
<!-- AC:END -->
