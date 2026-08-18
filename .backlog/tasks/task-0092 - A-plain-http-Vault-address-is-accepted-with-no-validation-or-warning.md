---
id: TASK-0092
title: 'A plain http:// Vault address is accepted with no validation or warning'
status: Done
assignee:
  - TASK-0119
created_date: '2026-08-14 14:06'
updated_date: '2026-08-18 09:31'
labels:
  - security-review
  - security
  - vault
dependencies: []
modified_files:
  - crates/proxy/src/config.rs
  - crates/proxy/src/vault.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/config.rs:396-398` (`addr` is a bare String), `crates/proxy/src/vault.rs:303-306`.

**What**: `Config::validate` never checks the Vault `addr` scheme; config tests pass with `addr = "http://127.0.0.1:8200"`. vaultrs accepts `http`. Verified against source.

**Why it matters**: a production config copied from the dev example keeps `http://`, and the Vault token plus every DEK plaintext transits the network in cleartext on every key operation. The proxy hard-refuses plaintext on both pgwire hops when TLS is configured but silently tolerates a fully plaintext KMS hop. Not even an INFO line distinguishes the two.

**Fix shape**: refuse an `http://` Vault addr (or warn loudly) unless an explicit `allow_insecure_addr = true` dev flag is set.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 A non-https Vault addr is refused unless an explicit insecure opt-in is set
- [x] #2 A test covers an http:// vault addr
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Fixed in TASK-0119 (branch code-review/TASK-0119). `VaultConfig` gains `allow_insecure_addr` (default `false`), and `Config::validate` now calls `VaultConfig::validate_addr` for any `[vault]` section, whether or not a `[[column]]` uses it. A `http://` addr is refused with a message naming both what travels over that channel and the `allow_insecure_addr = true` opt-in that accepts it; with the opt-in set it is accepted and a `tracing::warn!` records the choice. Any scheme other than `http`/`https` is refused outright.

Test: `config::tests::a_plaintext_vault_addr_is_refused_unless_it_is_opted_into` covers the refusal, the message naming the opt-in, the opt-in path, and the `https` norm. The existing config tests that used `addr = "http://127.0.0.1:8200"` or `addr = "a"` were moved to `https://bao.internal:8200` so they still fail for the reason each is about. `crates/proxy/tests/e2e_vault.rs` sets `allow_insecure_addr = true` — its fixture is a `-dev` OpenBao on plaintext http.
<!-- SECTION:NOTES:END -->
