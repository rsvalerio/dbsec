---
id: TASK-0090
title: >-
  The config file's own permissions are never checked, though it may hold an
  inline Vault token or DSN password
status: Triage
assignee: []
created_date: '2026-08-14 14:06'
labels:
  - security-review
  - security
  - config
dependencies: []
modified_files:
  - crates/proxy/src/config.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/config.rs:592-604` (`Config::load` has no mode check); contrast the enforced checks at `:627` (keyfile), `:434` (token_file), `:627` (downstream TLS key) via `check_secret_file_mode` (`:237-254`).

**What**: `check_secret_file_mode` rigorously refuses group- and world-readable `keys_file`, `token_file`, and downstream TLS key. But the config file itself may carry an inline `[vault] token` (explicitly supported, config.rs:398-402) or a `control_dsn` password, and `Config::load` reads it with no mode check. The zeroizing of the config text protects heap remanence, not file exposure. Verified against source.

**Why it matters**: a `0644` `dbsec.toml` with an inline token hands every local user the credential the module's own docs call "the credential that unwraps every DEK" — the exact failure mode SEC-29 exists to prevent. The keyfile is refused at 0644; the file holding the token that unwraps the same material is not.

**Fix shape**: apply `check_secret_file_mode` to the config path when the parsed config contains an inline `token` or a password-bearing `control_dsn`.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A world- or group-readable config that carries an inline secret is refused with the same check secrets get
- [ ] #2 A config that carries no inline secret is unaffected
- [ ] #3 A test covers a 0644 config with an inline vault token
<!-- AC:END -->
