---
id: TASK-0138
title: >-
  Every error is logged with Display only, so no #[source] cause the workspace
  attaches is ever rendered
status: Done
assignee:
  - TASK-0142
created_date: '2026-08-18 09:44'
updated_date: '2026-08-18 10:57'
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
- [x] #1 A failed control connection logs the io::Error under the tokio_postgres error, not just its top line
- [x] #2 A key-backend failure logs the vaultrs cause that DEFAULT_LOG_FILTER silences at its own target
- [x] #3 No renderer prints Error::ConfigParse's dropped toml source, so a credential-bearing config line still cannot reach the log
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Fixed in wave TASK-0142. New crates/proxy/src/diag.rs: `chain(&dyn Error) -> Chain<'_>`, a Display wrapper that walks source() and joins the links with ": ". Two deliberate properties: (a) a cause whose text the message above it already contains is not repeated — Error::Control, Error::Listen and Error::Hardening interpolate {source} into their own Display, so an unconditional join would print the same sentence twice before reaching the new link; the walk still descends past it, which is where the io::Error lives; (b) the walk is bounded at MAX_CAUSES = 8 and ends in ": …" rather than trusting a source() chain it does not own. Applied at the handling sites: main.rs (startup failed, failed to start runtime, proxy exited with error, both arms of log_session_error), resolve.rs (refresh_loop warn, the control-connection task warn) and vault.rs (check_token's two warns). Deliberately NOT applied in session.rs/rows.rs: session.rs logs and then propagates to log_session_error, which now renders the chain, and rows.rs::refuse only ever sees source-less proxy variants (is_refusal). Error::ConfigParse is untouched and still carries no #[source] — the renderer cannot reach around that, and main::tests::rendering_a_config_parse_failure_cannot_reach_the_line_it_choked_on loads a malformed credential-bearing DSN and asserts the rendered chain equals Display and contains no credential (AC3). AC1: resolve::tests::a_failed_control_connection_keeps_its_typed_cause now also asserts diag::chain renders the io::Error under the tokio_postgres error, with the password still absent. AC2: main::tests::a_key_backend_failure_reports_the_cause_the_vault_target_is_silenced_for. diag.rs has its own unit tests for the join, the no-cause case, the de-duplication and the depth bound. DEFAULT_LOG_FILTER and log_session_error doc comments updated: the vaultrs cause is now printed, not merely "reachable".
<!-- SECTION:NOTES:END -->
