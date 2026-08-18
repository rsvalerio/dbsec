---
id: TASK-0095
title: >-
  No Vault token renewal and grow-only key caches: revocation and token expiry
  are not handled until restart
status: Done
assignee:
  - TASK-0118
created_date: '2026-08-14 14:06'
updated_date: '2026-08-17 20:31'
labels:
  - security-review
  - vault
dependencies: []
modified_files:
  - crates/proxy/src/vault.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/vault.rs:284-295` (grow-only `deks`/`index_keys` caches, no TTL), `:300-347` (one-time static-token auth; no `renew`/`lookup` anywhere — grep-verified).

**What**: the proxy authenticates once with a static token used for the whole process lifetime and never renews it, and the key caches have no TTL or invalidation. Verified against source.

**Why it matters** (operational): (1) a TTL'd token (good practice) that expires mid-run is masked — cached keys keep working, so traffic looks healthy until the first cache miss then fails sessions at ERROR, pushing operators toward long-lived/root tokens. (2) Incident response that revokes the token or rotates a key in Vault has **zero effect** on a running proxy until restart — there is no revocation propagation.

**Fix shape**: add periodic token `lookup`/`renew` (warn as expiry approaches), and either a cache TTL/re-validation or a documented runbook note that revocation requires a proxy restart.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 The Vault token is periodically validated and a near-expiry token is surfaced rather than silently masked
- [x] #2 Key revocation propagation is either implemented via cache TTL or documented as requiring a restart
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Fixed in wave TASK-0118.

AC #1: added a `token_watch` task, spawned alongside the column refresher in `main::serve` and joined on the same shutdown watch. It calls `auth/token/lookup-self` once a minute through a new `KeyStore::token_status` seam and, when under ten minutes of lease remain, renews via `auth/token/renew-self` (`KeyStore::renew_token`). A lease running out that cannot be extended — not renewable, or renewal refused — is logged at WARN on every check naming the remaining TTL, so it is surfaced instead of being masked by the caches until the first miss. An unreachable Vault is `TokenCheck::Unknown`, never reported as an expiring token. The per-tick decision is factored into `VaultKeySource::check_token`, covered by four tests (healthy / renewed / expiring both ways / unknown) that need no timer. Both Vault responses echo the token back, so `id` and `client_token` are zeroized before their structs drop.

AC #2: taken as "documented as requiring a restart", with the reasoning for not adding a cache TTL recorded rather than left implicit — a TTL would put a Vault round-trip on the relay path and make Vault a per-request availability dependency, while buying nothing (deterministic index keys must not change under a running column, and a re-fetched DEK is the same DEK). Documented in the `vault` module docs and in plans/PLAN.md under a new "Vault token lease, and why revocation needs a restart" section; the deterministic-key exposure runbook's step 1 now says to restart the proxies after revoking.
<!-- SECTION:NOTES:END -->
