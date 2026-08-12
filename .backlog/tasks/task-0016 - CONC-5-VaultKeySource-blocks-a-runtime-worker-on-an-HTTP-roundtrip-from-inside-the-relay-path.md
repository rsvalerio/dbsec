---
id: TASK-0016
title: >-
  CONC-5: VaultKeySource blocks a runtime worker on an HTTP roundtrip from
  inside the relay path
status: To Do
assignee:
  - TASK-0052
created_date: '2026-08-11 19:14'
updated_date: '2026-08-11 22:42'
labels:
  - code-review-rust
  - async
  - vault
dependencies: []
modified_files:
  - crates/proxy/src/vault.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/vault.rs:95-100`, `crates/proxy/src/vault.rs:146-167`

**What**: `KeySource` is a synchronous trait, so the Vault implementation bridges back into the runtime:

```rust
fn block_on<T>(&self, fut: impl Future<Output = Result<T, CoreError>>) -> Result<T, CoreError> {
    tokio::task::block_in_place(|| self.handle.block_on(fut))
}
```

`key()` and `index_key()` call it on every cache miss. Those methods are reached from `FieldTransform::open`/`seal`, which run inside `RowDecryptor::on_frame` and `QueryRewriter::on_frame` — i.e. synchronously inside the relay loop, once per protected value. Three consequences:

1. **A worker thread is parked for a full Vault HTTP roundtrip.** `block_in_place` moves other tasks off the worker, but the thread itself is unavailable until the request completes, and there is no timeout on the Vault call.
2. **`block_in_place` panics outside a multi-thread runtime.** `main.rs:77` uses `Runtime::new()` (multi-thread), so production is fine — but any `#[tokio::test]` exercising this path uses the current-thread flavour by default and would panic rather than fail meaningfully. That is likely part of why `vault.rs` has no unit tests (see the test-coverage finding).
3. **No negative caching.** `key()` inserts into `self.deks` only on success, so a stored value carrying an unrecognized key id triggers a fresh Vault KV read *per value per row*. A result set of unopenable rows becomes one blocking HTTP request per cell.

**Why it matters**: The crypto path is the proxy's hot path, and this puts an unbounded-duration network call in the middle of it while occupying a runtime worker. Under a slow or degraded Vault, worker threads park on requests and the proxy stalls for every session, not just the one that missed. Point 3 turns a single malformed or legacy row into a Vault request storm.

The structural fix is to resolve keys asynchronously (prefetch at startup, or make the key lookup an async step outside the sync transform). If the sync trait must stay, the minimum is a timeout on each Vault call and a negative cache for unknown key ids.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Vault roundtrips reached from the relay path are bounded by a timeout
- [ ] #2 Unknown key ids are negatively cached (with a bound/TTL) so one unopenable column does not issue a Vault request per value
- [ ] #3 The multi-thread-runtime requirement of block_in_place is documented on VaultKeySource, or the design is changed so it no longer applies
<!-- AC:END -->
