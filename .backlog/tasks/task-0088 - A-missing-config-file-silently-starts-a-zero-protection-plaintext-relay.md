---
id: TASK-0088
title: A missing config file silently starts a zero-protection plaintext relay
status: Done
assignee:
  - TASK-0120
created_date: '2026-08-14 14:06'
updated_date: '2026-08-17 20:28'
labels:
  - security-review
  - security
  - config
dependencies: []
modified_files:
  - crates/proxy/src/main.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/main.rs:189-198` (`load_config`).

**What**: with no CLI argument and no `dbsec.toml` present, startup falls to `Config::default().validated()`. The default config has empty `columns` and no `[tls.*]`, so the proxy binds and relays everything with **no encryption, no TLS, and no column protection**. The only evidence is `protected_columns = 0` in one INFO line. An explicitly-wrong path fails hard (good); only the implicit-default case fails open. Verified against source (`Config::default` fields).

**Why it matters**: a systemd unit whose `WorkingDirectory` changes, or a container whose config volume mounts to the wrong path with no argument passed, silently turns the proxy into a transparent plaintext passthrough. This is the "fail-open at startup" risk, documented only in a code comment. Mitigated in practice by the loopback default bind, but a reverse-proxied or port-forwarded deployment removes that mitigation.

**Fix shape**: refuse to start when no config is found unless an explicit opt-in flag (e.g. `--plain-relay`) is given.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Starting with no argument and no dbsec.toml present refuses to run unless an explicit plaintext-relay opt-in is set
- [x] #2 The refusal message names the missing config and the opt-in flag
- [x] #3 A CLI test covers the no-config, no-flag case
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Implemented in TASK-0120 (branch code-review/TASK-0120).

- `main.rs` gained an `Args` parser (`--plain-relay`, `--allow-core-dumps`, one optional config path). An unknown `-`-prefixed argument is now a usage error rather than a config path, so a mistyped opt-in cannot read as a missing file.
- `load_config` refuses with `Error::NoConfig` when no path was given and `dbsec.toml` is absent; the message names both the file and `--plain-relay`. With the flag, the old built-in-defaults behaviour is kept and a WARN line records that the process is relaying in plaintext.
- Tests: `crates/proxy/src/main.rs` unit cases (`a_missing_config_refuses_to_start_unless_the_plain_relay_opt_in_is_given`, `the_plain_relay_opt_in_never_overrides_a_config_that_is_there`, argument-parsing cases) and `crates/proxy/tests/cli.rs` process-level cases (`no_argument_and_no_config_file_refuses_to_start`, `the_plain_relay_opt_in_falls_back_to_the_default_listen_address`, `an_unknown_option_exits_non_zero_with_the_usage_line`). The old `no_argument_and_no_config_file_falls_back_to_the_default_listen_address` case now runs behind the opt-in.
- `load_config` takes the default path as a parameter so the unit cases need no process-wide `chdir`; the real discovery path stays covered by tests/cli.rs.
- Makefile `run` target and README document the fail-closed startup.
<!-- SECTION:NOTES:END -->
