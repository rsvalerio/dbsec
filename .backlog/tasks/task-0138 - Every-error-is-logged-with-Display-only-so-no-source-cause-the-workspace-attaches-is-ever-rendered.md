---
id: TASK-0138
title: >-
  Every error is logged with Display only, so no #[source] cause the workspace
  attaches is ever rendered
status: To Do
assignee:
  - TASK-0142
created_date: '2026-08-18 09:44'
updated_date: '2026-08-18 10:00'
labels:
  - code-review-rust
  - error-handling
dependencies: []
modified_files:
  - crates/proxy/src/main.rs
  - crates/proxy/src/resolve.rs
  - crates/proxy/src/vault.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/main.rs:230`, `crates/proxy/src/main.rs:247`, `crates/proxy/src/main.rs:658`, `crates/proxy/src/resolve.rs:87`, `crates/proxy/src/vault.rs:626`

**What**: every site that reports an error does it as `tracing::error!(error = %e, ...)` /
`tracing::warn!(error = %e, ...)`, which formats `Display` and stops there.
`tracing_subscriber::fmt` does not walk `std::error::Error::source()`, so nothing in the
process ever prints the causes the error types go out of their way to keep:
`dbsec_core::Error::KeyBackend`'s boxed `vaultrs` error, `Error::ConfigRead`,
`Error::Listen`, `Error::Hardening`, and now `Error::Control` / `Error::VaultToken`. For
`KeyBackend` the loss is total — its `Display` is `key source: {context}` with no
`{source}` — and `DEFAULT_LOG_FILTER` deliberately silences the `vaultrs`/`rustify`
targets on the grounds that "the library's view of it is still reachable through the error
chain", which is true only for a reader who has a debugger.

**Why it matters**: the whole ERR-9 investment (TASK-0030, TASK-0059, TASK-0078) buys
nothing an operator can see. A control connection that fails at boot logs
"control connection to db:5432: error connecting to server" — the `io::Error` saying
*Connection refused* vs *Certificate verify failed* is one link further down and never
printed. Same for a Vault 403 vs a connection refused behind `key source: fetching DEK`.

**Fix shape**: a small chain renderer (`fn causes(e: &dyn std::error::Error) -> String`
joining `source()` with `": "`, or `tracing`'s `error = &e as &dyn Error` plus a subscriber
layer that records the chain) used at the handling sites — `main`'s two startup/exit
reports, `log_session_error`, `refresh_loop`'s warn, and `check_token`'s warns. Watch
SEC: `Error::ConfigParse` deliberately drops its `toml` source because printing it would
echo a credential-bearing config line, so a chain renderer must not reintroduce that.

**Origin**: discovered during TASK-0126 while fixing TASK-0078.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A failed control connection logs the io::Error under the tokio_postgres error, not just its top line
- [ ] #2 A key-backend failure logs the vaultrs cause that DEFAULT_LOG_FILTER silences at its own target
- [ ] #3 No renderer prints Error::ConfigParse's dropped toml source, so a credential-bearing config line still cannot reach the log
<!-- AC:END -->
