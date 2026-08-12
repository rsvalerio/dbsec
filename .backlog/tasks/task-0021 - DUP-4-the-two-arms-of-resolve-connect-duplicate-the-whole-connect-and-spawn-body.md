---
id: TASK-0021
title: >-
  DUP-4: the two arms of resolve::connect duplicate the whole connect-and-spawn
  body
status: Done
assignee:
  - TASK-0056
created_date: '2026-08-11 19:15'
updated_date: '2026-08-12 16:28'
labels:
  - code-review-rust
  - duplication
  - resolve
dependencies: []
modified_files:
  - crates/proxy/src/resolve.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/resolve.rs:65-92`

**What**: `connect` matches on whether upstream TLS is configured and each arm repeats the same nine lines, differing only in the connector value passed to `tokio_postgres::connect`:

```rust
let (client, connection) = tokio_postgres::connect(dsn, <connector>)
    .await
    .map_err(|e| Error::Control(e.to_string()))?;
tokio::spawn(async move {
    if let Err(e) = connection.await {
        tracing::warn!(error = %e, "control connection ended with error");
    }
});
Ok(client)
```

`tokio_postgres::connect` is generic over `T: MakeTlsConnect<Socket>`, so the shared tail extracts cleanly into one generic helper that both arms call with `MakeRustlsConnect` and `NoTls` respectively.

**Why it matters**: Low severity on its own — nine lines, two copies. It earns a task because both copies are on the list of things [[task-0014]] must change: adding a connect timeout, a distinct error variant, and a query timeout means making the same edit twice, and the divergence between the two copies is the bug that eventually ships. Fixing the duplication first makes that change a one-place edit. Worth doing as part of TASK-0014 rather than separately.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 The connect-and-spawn body exists once, as a generic helper over MakeTlsConnect, called by both arms
- [x] #2 Behaviour is unchanged: the same error mapping and the same connection-task warning on both paths
<!-- AC:END -->
