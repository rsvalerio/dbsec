---
id: TASK-0078
title: >-
  ERR-9: resolve.rs and the token-file read still flatten typed error causes
  into Strings
status: Done
assignee:
  - TASK-0126
created_date: '2026-08-14 12:34'
updated_date: '2026-08-18 09:40'
labels:
  - code-review-rust
  - error-handling
dependencies: []
modified_files:
  - crates/proxy/src/resolve.rs
  - crates/proxy/src/config.rs
  - crates/proxy/src/main.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/resolve.rs:141`, `crates/proxy/src/resolve.rs:215`, `crates/proxy/src/config.rs:440`

**What**: three sites survived the wave-9 sweep that gave key-backend failures a typed
`#[source]` (TASK-0059) and dbsec-core structured causes (TASK-0030):

- `resolve.rs:141` and `resolve.rs:215` map `tokio_postgres::Error` into
  `Error::Control(e.to_string())`. A tokio_postgres error carries an `io::Error` or TLS
  error as its source — the part that tells "connection refused" apart from "certificate
  verify failed" apart from "password authentication failed" — and `to_string()` keeps
  only the top-line message.
- `config.rs:440` maps the token-file `io::Error` into `Error::Vault(format!(...))`,
  although `Error` already has the `ConfigRead { path, #[source] }` shape for exactly
  this (a config-adjacent file read that failed).

**Why it matters**: the control connection is the most failure-prone startup step (its own
docs say so), and it is exactly where an operator needs the full chain. The codebase's
own convention after waves 5/9 is that causes survive as `#[source]`; these are the
stragglers.

**Fix shape**: an `Error::Control`-like variant carrying `#[source] tokio_postgres::Error`
(or a boxed dyn source, matching `KeyBackend`), and the token-file read reusing the
`ConfigRead` pattern or an equivalent sourced variant.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 A control-connection failure exposes the tokio_postgres cause through std::error::Error::source()
- [x] #2 A token-file read failure names the path and keeps the io::Error as a source
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Error::Control is now { host, #[source] tokio_postgres::Error } and both resolve.rs sites carry the typed cause (the endpoint is parsed out of the DSN the same way ControlTimeout does it, so no password is echoed). Error::Vault(String) had exactly one producer — the [vault] token_file read — and was replaced by Error::VaultToken { path, #[source] io::Error }; the orphaned Vault variant was removed. New tests: resolve::tests::a_failed_control_connection_keeps_its_typed_cause (walks err -> tokio_postgres -> io::Error) and config::tests::an_unreadable_token_file_names_the_path_and_keeps_its_cause.
<!-- SECTION:NOTES:END -->
