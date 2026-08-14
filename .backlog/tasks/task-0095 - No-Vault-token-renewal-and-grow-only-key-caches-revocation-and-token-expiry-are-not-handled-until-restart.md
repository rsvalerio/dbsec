---
id: TASK-0095
title: >-
  No Vault token renewal and grow-only key caches: revocation and token expiry
  are not handled until restart
status: Triage
assignee: []
created_date: '2026-08-14 14:06'
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
- [ ] #1 The Vault token is periodically validated and a near-expiry token is surfaced rather than silently masked
- [ ] #2 Key revocation propagation is either implemented via cache TTL or documented as requiring a restart
<!-- AC:END -->
