---
id: TASK-0047
title: >-
  SEC-5: control_dsn carries the database password in a plain String on a
  Debug-deriving Config
status: Done
assignee:
  - TASK-0053
created_date: '2026-08-11 21:05'
updated_date: '2026-08-12 16:51'
labels:
  - code-review-rust
  - security
  - config
dependencies: []
modified_files:
  - crates/proxy/src/config.rs
  - crates/proxy/src/main.rs
  - crates/proxy/src/resolve.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/config.rs:27`, `crates/proxy/src/config.rs:10-32`

**What**: `Config` derives `Debug` and holds the control DSN as an unprotected `String`:

```rust
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    ...
    /// DSN for the startup control connection ...
    /// e.g. `postgres://dbsec:secret@127.0.0.1:5432/app`.
    pub control_dsn: Option<String>,
```

The doc comment's own example spells out that this field contains a password. Any `{:?}` of `Config` — a debug log, a panic payload, an `expect` message that formats it — prints the DSN with the password in it. The value is also passed by reference into `resolve::resolve_columns(dsn, ...)` (`crates/proxy/src/main.rs:123`) and lives in the `Config` for the process lifetime with no zeroization, so it sits in the heap and in any core dump.

This is the same class of defect as [[task-0010]] but a different field with a different fix. [[task-0010]] covers `VaultConfig::token`, where the whole field is the secret and a `Zeroizing`/`SecretString` newtype is enough. A DSN is a mixed value — the host, port and database name are useful in logs and startup diagnostics, and only the userinfo component is sensitive — so redacting it means parsing the URL and masking the password, not hiding the field.

**Why it matters**: The control DSN is the credential for the account that reads `pg_catalog` at startup, and in every deployment shape the project documents it is a real Postgres login on the same database holding the protected columns. It is the second-highest-value secret in the process after the Vault token, and it is the one with no protection at all.

The exposure surface is bigger than [[task-0010]]'s because a DSN is the kind of value that gets logged deliberately. `serve()` already emits a startup `tracing::info!` with `listen`, `upstream` and `protected_columns` (`crates/proxy/src/main.rs:133-140`); adding `control_dsn` to that line, or a `?config` while debugging a startup failure, is a one-word change that ships a password to the log aggregator. Neither the type nor the derive gives anyone a reason to hesitate.

Startup failures make this concrete rather than hypothetical: connecting the control connection is the most failure-prone step at boot (wrong host, wrong password, TLS mismatch), and it is exactly when an operator reaches for a debug log of the config.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 control_dsn is a type whose Debug impl redacts the password while keeping host, port and database name legible
- [x] #2 The redacting type is used everywhere the DSN is held or passed, including the resolve::resolve_columns call site
- [x] #3 A test asserts that formatting a Config containing a password-bearing control_dsn does not emit the password
- [x] #4 A test asserts the redacted form still shows host, port and database so startup diagnostics stay useful
<!-- AC:END -->
