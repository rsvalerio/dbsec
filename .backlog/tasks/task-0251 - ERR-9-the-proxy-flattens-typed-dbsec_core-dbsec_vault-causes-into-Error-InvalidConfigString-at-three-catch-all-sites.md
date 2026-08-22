---
id: TASK-0251
title: >-
  ERR-9: the proxy flattens typed dbsec_core / dbsec_vault causes into
  Error::InvalidConfig(String) at three catch-all sites
status: Triage
assignee: []
created_date: '2026-08-21 19:55'
labels:
  - code-review-rust
  - error-handling
dependencies: []
modified_files:
  - crates/proxy/src/config.rs
  - crates/proxy/src/main.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/config.rs:220`, `crates/proxy/src/config.rs:644`, `crates/proxy/src/main.rs:223`

**What**:
```rust
// config.rs:220-223
dbsec_core::keys::check_secret_file_mode(path, holds)
    .map_err(|e| Error::InvalidConfig(e.to_string()))
// config.rs:642-645
self.policy().validate().map_err(|e| match e {
    dbsec_core::Error::Policy(msg) => Error::InvalidConfig(msg),
    other => Error::InvalidConfig(other.to_string()),
})?;
// main.rs:223
other => Error::InvalidConfig(other.to_string()),
```
`check_secret_file_mode` returns a `dbsec_core::Error` carrying the `io::Error` (ENOENT vs EACCES vs a mode refusal) as a source; `to_string()` drops the chain that `diag::chain` at the startup site (main.rs:443) exists to render. The `other =>` arms are catch-alls that will silently flatten any variant either crate adds later. Proxy-side twin of TASK-0204 (vault) and the part of TASK-0078 not in its scope.

**Why it matters**: a missing keyfile and a world-readable keyfile produce the same `invalid config: ...` top line with no `source()` to walk, contradicting the crate's own TASK-0138 stance that handling sites render the chain.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Error::InvalidConfig (or a new variant) keeps the dbsec_core::Error / dbsec_vault::Error as #[source] instead of to_string(); the three sites no longer stringify a typed error
- [ ] #2 A test asserts diag::chain of a config refusal caused by an unreadable keys_file includes the underlying io message and names the path
<!-- AC:END -->
