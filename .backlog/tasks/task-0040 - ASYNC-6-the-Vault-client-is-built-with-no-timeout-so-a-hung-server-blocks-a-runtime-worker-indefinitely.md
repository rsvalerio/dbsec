---
id: TASK-0040
title: >-
  ASYNC-6: the Vault client is built with no timeout, so a hung server blocks a
  runtime worker indefinitely
status: To Do
assignee:
  - TASK-0052
created_date: '2026-08-11 19:36'
updated_date: '2026-08-11 22:42'
labels:
  - code-review-rust
  - async
  - reliability
dependencies: []
modified_files:
  - crates/proxy/src/vault.rs
  - crates/proxy/src/config.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/vault.rs:48-54`

**What**: The client is built without a timeout:

```rust
let settings = VaultClientSettingsBuilder::default()
    .address(&config.addr)
    .token(token.as_str())
    .build()
    .map_err(|e| Error::Vault(e.to_string()))?;
```

`.timeout(...)` is never set, so every Vault roundtrip in this module inherits the transport default rather than a bound the proxy chose:

- `transit::generate::data_key` and `kv2::set` at startup (`vault.rs:56-79`)
- `fetch_dek` — a KV read plus a Transit decrypt (`vault.rs:102-121`)
- `fetch_or_create_index_key` — a KV read plus a KV write (`vault.rs:123-143`)

The last two are the sharp ones. They are reached from the **sync** `KeySource` methods (`vault.rs:151-167`), which run them through `block_on` (`vault.rs:95-100`):

```rust
tokio::task::block_in_place(|| self.handle.block_on(fut))
```

and `KeySource::key` is called from inside the relay's transform closure — on the data path, per value, on a cache miss. A Vault server that accepts the connection and then stops responding (a hung backend, a partitioned network with no RST, a seal in progress) parks a runtime worker thread on that future with nothing to time it out. [[task-0016]] covers the `block_in_place` shape itself; the missing timeout is what turns "briefly blocks a worker" into "permanently consumes one".

A cache miss is client-reachable: the key id comes out of the stored ciphertext (`envelope`), so reading rows written under different DEKs drives `fetch_dek` calls.

**Why it matters**: The proxy's worker pool is the whole of its capacity. Each hung Vault call takes one worker out of it for the process's lifetime, and there is no retry, no backoff, and no error to surface — the session just stops. The startup calls are less severe (no listener yet, [[task-0014]] covers the equivalent gap on the control connection) but share the fix. Every external call in this crate should carry a timeout the proxy sets, so the failure is a bounded error the caller can log and fail on rather than an unbounded stall.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The Vault client is constructed with an explicit request timeout, configurable from [vault] with a documented default
- [ ] #2 Confirm and record what vaultrs 0.7 / its transport defaults to when no timeout is set, so the finding's premise is verified rather than assumed
- [ ] #3 A Vault call that exceeds the timeout returns Error::Vault naming the operation, and the relay fails the session rather than stalling
- [ ] #4 The runtime-path calls (fetch_dek, fetch_or_create_index_key) cannot hold a worker thread past the timeout
<!-- AC:END -->
