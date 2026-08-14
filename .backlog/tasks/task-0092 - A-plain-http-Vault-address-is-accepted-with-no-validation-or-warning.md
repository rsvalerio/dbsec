---
id: TASK-0092
title: 'A plain http:// Vault address is accepted with no validation or warning'
status: Triage
assignee: []
created_date: '2026-08-14 14:06'
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
- [ ] #1 A non-https Vault addr is refused unless an explicit insecure opt-in is set
- [ ] #2 A test covers an http:// vault addr
<!-- AC:END -->
