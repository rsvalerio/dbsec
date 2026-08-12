---
id: TASK-0007
title: >-
  SEC-25: index-key minting is a read-modify-write race that can drop a key
  permanently
status: To Do
assignee:
  - TASK-0052
created_date: '2026-08-11 19:12'
updated_date: '2026-08-11 22:42'
labels:
  - code-review-rust
  - security
  - vault
dependencies: []
modified_files:
  - crates/proxy/src/vault.rs
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/vault.rs:123-143`

**What**: `fetch_or_create_index_key` reads the entire `index_keys` map, adds one entry, and writes the whole map back. There is no CAS — `vaultrs::kv2::set` is an unconditional write, and KV v2's `cas` option is not used. The code documents the two-proxy race in a comment ("Two proxies racing here could each mint one and last-write-wins — provision the secret up front if that matters") but nothing enforces it.

The window is wider than the comment suggests. It is not only two proxies starting at once: a single long-running proxy that first touches column A at 10:00 and column B at 14:00 writes back the map it read at 14:00, so anything another instance stored in between is overwritten. Two proxies each minting a *different* column's key at the same time lose one of them.

**Why it matters**: A lost index key is the same unrecoverable outcome as [[task-0006]] — blind indexes stop matching, FPE values stop detokenizing, tokens stop correlating — but arrives from ordinary multi-instance operation rather than an error. Any HA deployment (two proxies behind a load balancer, a rolling restart, a Kubernetes deployment with `maxSurge`) hits it. It also fails silently: the losing proxy has the key it minted cached in `index_keys` for its whole lifetime, so it keeps working correctly until it restarts, at which point it reads the winner's map and starts producing different indexes for the same plaintext.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Index-key creation is atomic against concurrent writers — KV v2 check-and-set on the read version, per-key paths instead of one shared map, or a documented startup-only provisioning step that refuses to mint at runtime
- [ ] #2 A losing writer detects the conflict and re-reads rather than overwriting
- [ ] #3 The behaviour under concurrent minting is documented in the module docs and covered by a test or an e2e case with two proxies
<!-- AC:END -->
