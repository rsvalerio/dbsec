---
id: TASK-0090
title: >-
  The config file's own permissions are never checked, though it may hold an
  inline Vault token or DSN password
status: Done
assignee:
  - TASK-0120
created_date: '2026-08-14 14:06'
updated_date: '2026-08-17 20:29'
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
- [x] #1 A world- or group-readable config that carries an inline secret is refused with the same check secrets get
- [x] #2 A config that carries no inline secret is unaffected
- [x] #3 A test covers a 0644 config with an inline vault token
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Implemented in TASK-0120 (branch code-review/TASK-0120).

- `Config::load` now applies `check_secret_file_mode` to the config path itself whenever `Config::inline_secret` reports one: an inline `[vault] token`, or a `control_dsn` that carries a password (decided by `tokio_postgres`' own parser via the new `Dsn::carries_password`; an unparseable DSN counts as secret-bearing, which fails closed). A `token_file` is deliberately not an inline secret — that path is already checked on its own.
- The check runs in `load` rather than `validate`, because it is a property of the file this config came from; a programmatically built config has no file behind it.
- `check_secret_file_mode` gained a `holds` argument so the refusal names the credential ("it holds an inline [vault] token"), which is what makes the new config-file case readable rather than looking like a bug. The three existing call sites name theirs too.
- Tests: `a_config_holding_an_inline_secret_must_be_readable_only_by_its_owner` (0600 accepted, 0640/0644 refused with mode and credential named, plus the DSN-password case asserting the refusal itself does not echo the password) and `a_config_with_no_inline_secret_is_unaffected_by_its_mode`.
- `crates/proxy/tests/common/mod.rs` now chmods the e2e config to 0600: it carries a `control_dsn` password and, in Vault mode, an inline token, so `File::create` under the default umask would have made every e2e suite fail to start. `make e2e` and `make e2e-vault` both verified green.
<!-- SECTION:NOTES:END -->
