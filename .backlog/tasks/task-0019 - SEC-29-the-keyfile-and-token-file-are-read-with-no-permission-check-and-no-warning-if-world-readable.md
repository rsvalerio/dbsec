---
id: TASK-0019
title: >-
  SEC-29: the keyfile and token file are read with no permission check, and no
  warning if world-readable
status: To Do
assignee:
  - TASK-0053
created_date: '2026-08-11 19:15'
updated_date: '2026-08-11 22:42'
labels:
  - code-review-rust
  - security
  - config
dependencies: []
modified_files:
  - crates/proxy/src/config.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/config.rs:102-113`, `crates/proxy/src/config.rs:190-197`

**What**: Two files hold secrets and both are opened with a plain read, with no inspection of their mode:

- `keys_file` — `FileKeySource::load` reads a TOML file containing the raw 32-byte master keys and every deterministic index key as hex. The e2e harness's own fixture (`crates/proxy/tests/common/mod.rs:59-73`) shows the shape: `[keys]` and `[index_keys]` tables of raw hex.
- `VaultConfig::token_file` (`config.rs:105`) — `std::fs::read_to_string(path)` on a file holding the Vault token.

Neither path checks `st_mode`, neither refuses a world- or group-readable file, and neither logs a warning. `Config::validate` (line 199) does careful semantic validation — mutually exclusive key sources, duplicate columns, `searchable` requiring `encrypt` — but nothing about the security posture of the files it points at.

**Why it matters**: SEC-29 asks for exactly this check, and the keyfile is the single artifact whose disclosure defeats the entire product: with it, everything at rest decrypts. A `0644` keyfile is the most likely real-world misconfiguration — it is what you get from `cp`, from a config-management template with no explicit mode, from a Docker `COPY`, or from an editor that recreates the file on save. Every one of those is silent today. `ssh` refuses to use a private key with loose permissions for the same reason; the check is a `metadata().permissions().mode() & 0o077` and a clear error.

Two related notes for the same change:

- `config.rs:105` and `config.rs:191` use `std::fs::read_to_string`. The token-file read is reached from `VaultKeySource::connect`, an `async fn` — blocking I/O on the runtime (CONC-5). It is once at startup so the impact is nil, but it is worth fixing in the same pass.
- `Config::validate` calls `vault.token()?` purely to check resolvability, so the token file is read twice per startup.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 keys_file and token_file are rejected (or loudly warned about, with the decision documented) when group- or world-readable on unix
- [ ] #2 The check has a documented behaviour on non-unix targets rather than a compile error
- [ ] #3 A test with tempfile covers both the 0600 accept and the 0644 reject paths
- [ ] #4 The token file is read once per startup rather than once in validate and again in connect
<!-- AC:END -->
