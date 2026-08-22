---
id: TASK-0208
title: >-
  TEST-5: dbsec-vault's own public API in lib.rs (validate_addr, resolve_token,
  resolve, check_token_file, Secret redaction) has no tests inside the crate —
  coverage lives only in crates/proxy/src/config.rs
status: Triage
assignee: []
created_date: '2026-08-21 19:36'
labels:
  - code-review-rust
  - tests
dependencies: []
modified_files:
  - crates/vault/src/lib.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/vault/src/lib.rs:208` (also `crates/vault/src/lib.rs:230`, `crates/vault/src/lib.rs:270`, `crates/vault/src/lib.rs:284`, `crates/vault/src/lib.rs:95`)

**What**: Every test in the crate is in `source.rs`; `lib.rs` has no `#[cfg(test)]` module. `VaultConfig::validate_addr` (https / http+allow / http refused / other scheme / not-a-URL), `resolve_token` (token vs token_file, both, neither, trimming, the mode check), `resolve` (zero timeout), `check_token_file` and `Secret`'s `Debug` redaction are exercised only by `crates/proxy/src/config.rs` tests (e.g. lines 942, 983-988). `cargo test -p dbsec-vault` — what a contributor or a downstream packager runs — does not cover the crate's configuration surface at all.

**Why it matters**: TEST-5 — the crate is published standalone; a behaviour change to the address or token rules would pass the crate's own test suite and only be caught by a sibling crate that a downstream user does not have. The `Secret` redaction in particular is a security property with no test anywhere (`{:?}` on a config with a token must not print it).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 lib.rs has unit tests covering every validate_addr branch, resolve_token's four source combinations plus trimming and the permissive-mode refusal, resolve's zero-timeout refusal, and Secret's Debug output not containing the value
- [ ] #2 cargo test -p dbsec-vault runs them without needing the proxy crate
<!-- AC:END -->
