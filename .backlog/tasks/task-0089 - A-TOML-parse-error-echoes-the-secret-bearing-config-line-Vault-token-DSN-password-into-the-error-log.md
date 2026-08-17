---
id: TASK-0089
title: >-
  A TOML parse error echoes the secret-bearing config line (Vault token, DSN
  password) into the error log
status: To Do
assignee:
  - TASK-0120
created_date: '2026-08-14 14:06'
updated_date: '2026-08-17 20:04'
labels:
  - security-review
  - security
  - config
dependencies: []
modified_files:
  - crates/proxy/src/config.rs
  - crates/proxy/src/main.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/config.rs:601-602` (`ConfigParse` Display), `crates/proxy/src/main.rs:165-170` (`error!` logs it).

**What**: `Config::load` wraps a `toml::from_str` failure in an error whose Display is `"parsing config {path}: {source}"`, and `main` logs it. toml 0.8.23's error Display embeds the offending source line verbatim. Reproduced against the locked version: a lost closing quote on `token = "..."` (or a `control_dsn` password line) prints the whole secret line to stderr/journald. This defeats the crate's otherwise meticulous `Secret`/`Dsn` redaction, which only protects successfully-parsed values. The core crate already avoids this for the keyfile (`KeyFileParse` Display omits the source); the proxy's `ConfigParse` does not.

**Why it matters**: an operator fat-fingering the config drops the Vault token or DB password into every log pipeline that collects stderr.

**Fix shape**: render the toml error's message/span without its source snippet, or scrub the echoed line, so a parse failure cannot print secret-bearing config text.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A config parse error no longer prints the offending source line into logs
- [ ] #2 A test induces a parse error on a token line and asserts the secret is absent from the rendered error
<!-- AC:END -->
