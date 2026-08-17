---
id: TASK-0083
title: >-
  Vault TLS verification is not pinned, so an env var can silently disable it
  (inverted semantics)
status: To Do
assignee:
  - TASK-0119
created_date: '2026-08-14 14:06'
updated_date: '2026-08-17 20:03'
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
- [ ] #1 The Vault client sets certificate verification explicitly rather than inheriting the env default
- [ ] #2 VAULT_SKIP_VERIFY cannot silently disable verification for a proxy that intends to verify
- [ ] #3 A test asserts the built client verifies the Vault certificate
<!-- AC:END -->
