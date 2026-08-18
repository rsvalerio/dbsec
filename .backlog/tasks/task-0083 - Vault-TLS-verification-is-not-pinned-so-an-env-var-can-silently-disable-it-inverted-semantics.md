---
id: TASK-0083
title: >-
  Vault TLS verification is not pinned, so an env var can silently disable it
  (inverted semantics)
status: Done
assignee:
  - TASK-0119
created_date: '2026-08-14 14:06'
updated_date: '2026-08-17 20:59'
labels:
  - security-review
  - security
  - vault
  - tls
dependencies: []
modified_files:
  - crates/proxy/src/vault.rs
  - crates/proxy/src/main.rs
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/vault.rs:303-312` (client built without `verify`), `crates/proxy/src/main.rs:75` (`DEFAULT_LOG_FILTER` sets `vaultrs=off`).

**What**: `VaultClientSettingsBuilder` sets only `address`, `token`, and `timeout` — never `.verify(true)`. The `verify` field therefore takes vaultrs 0.7.4's env-driven default, which reads `VAULT_SKIP_VERIFY` with semantics **inverted** from the Vault CLI: values `0`, `f`, `false` yield `verify = false`, which flows to `danger_accept_invalid_certs(true)`. Confirmed against the locked vaultrs 0.7.4 source (`default_verify`, `VaultClient::new`).

**Why it matters**: an operator hardening the deployment with the natural Vault-CLI idiom `VAULT_SKIP_VERIFY=false` ("do verify") silently disables certificate verification on the channel that carries the Vault token, every plaintext Transit DEK, and every deterministic index key. A MITM on the proxy->Vault hop then captures the entire key hierarchy. vaultrs emits one WARN, which the default `vaultrs=off` log filter suppresses. Inconsistent with the codebase's own bar (tls.rs pins the crypto provider explicitly, SEC-8). Independently reported by two reviewers.

**Fix shape**: set `.verify(true)` explicitly in `connect()` (or expose it as a config field), decide deliberately whether to honor `VAULT_CACERT`/`VAULT_CAPATH`, and consider filtering vaultrs to `warn` rather than `off`.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 The Vault client sets certificate verification explicitly rather than inheriting the env default
- [x] #2 VAULT_SKIP_VERIFY cannot silently disable verification for a proxy that intends to verify
- [x] #3 A test asserts the built client verifies the Vault certificate
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Fixed in TASK-0119 (branch code-review/TASK-0119). `vault::client_settings` now pins `.verify(true)` explicitly and pre-parses `addr` as a URL before handing it to vaultrs; `VAULT_SKIP_VERIFY` can no longer decide verification and is reported at WARN when present (its value is passed in as an argument so the report is testable without mutating the process environment). `VAULT_CACERT`/`VAULT_CAPATH` are deliberately still honoured — they only add trust roots. `DEFAULT_LOG_FILTER` keeps `vaultrs=off`, with a note recording that the only security-relevant vaultrs WARN is now unreachable. Tests: `the_vault_client_verifies_the_server_certificate`, `vault_skip_verify_can_neither_disable_verification_nor_pass_unreported`.
<!-- SECTION:NOTES:END -->
