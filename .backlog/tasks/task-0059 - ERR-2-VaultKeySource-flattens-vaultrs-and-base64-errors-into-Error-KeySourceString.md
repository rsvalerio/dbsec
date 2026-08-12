---
id: TASK-0059
title: >-
  ERR-2: VaultKeySource flattens vaultrs and base64 errors into
  Error::KeySource(String)
status: Triage
assignee: []
created_date: '2026-08-12 11:03'
labels:
  - code-review-rust
  - errors
dependencies: []
modified_files:
  - crates/proxy/src/vault.rs
  - crates/core/src/lib.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/vault.rs:119`, `crates/proxy/src/vault.rs:120`, `crates/proxy/src/vault.rs:140`, `crates/proxy/src/vault.rs:183`, `crates/proxy/src/vault.rs:186`

**What**: TASK-0030 gave `dbsec_core::Error` typed variants for the file key
source (`KeyFileRead`/`KeyFileWrite`/`KeyFileParse`, each with `#[source]`), and
left `Error::KeySource(String)` as the variant for backends with no typed cause
to keep. The Vault/OpenBao key source is still one of those: every failure it
reports is `format!`ed into that String.

```rust
.map_err(|e| CoreError::KeySource(format!("transit unwrap: {e}")))?;
.map_err(|e| CoreError::KeySource(format!("storing index key {name}: {e}")))?;
CoreError::KeySource("stored index key is not valid hex".into())
```

The `vaultrs::error::ClientError` behind those messages is destroyed at
construction, so `source()` stops at dbsec-core and no caller can tell a 403
from a connection refused from a missing KV path.

**Why it matters**: same ERR-2/ERR-10 cost as TASK-0030, on the key backend
that actually runs in production. An operator debugging a proxy that cannot
unwrap a DEK gets one flat line and has to substring-match it. Fixing this
needs a cross-crate decision that TASK-0030 deliberately did not take: either
`Error::KeySource` grows an optional boxed `#[source]`, or the proxy stops
routing its backend failures through the core error type. `Error` is already
`#[non_exhaustive]`, so either shape is a non-breaking change now.

**Origin**: discovered during TASK-0054 (wave5) while fixing TASK-0030.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Vault key source failures carry their underlying cause (vaultrs error, base64/hex decode error) via #[source] rather than a formatted String
- [ ] #2 std::error::Error::source() returns the backend cause for errors originating in VaultKeySource
<!-- AC:END -->
