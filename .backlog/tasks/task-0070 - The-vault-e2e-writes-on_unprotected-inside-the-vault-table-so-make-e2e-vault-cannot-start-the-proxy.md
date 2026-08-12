---
id: TASK-0070
title: >-
  The vault e2e writes on_unprotected inside the [vault] table, so make
  e2e-vault cannot start the proxy
status: Done
assignee: []
created_date: '2026-08-12 19:32'
updated_date: '2026-08-12 19:34'
labels:
  - code-review-rust
  - test-quality
dependencies: []
modified_files:
  - crates/proxy/tests/common/mod.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/tests/common/mod.rs:216`

**What**: `spawn_proxy` renders `{key_source}` and then `{on_unprotected}` into the config
template. For `Keys::File` the key source is a single top-level `keys_file = …` line and the
order is harmless, but for `Keys::Vault` it is a whole `[vault]` section — so the
`on_unprotected = "warn"` line that follows lands *inside* that table. The proxy refuses the
config with `unknown field on_unprotected, expected one of addr, token, token_file, mount,
path, transit_mount, transit_key, timeout_secs` and never starts, so
`vault_key_source_survives_restarts` fails at the readiness assert in `spawn_with_config`.

**Why it matters**: `make e2e-vault` (and `ops verify qa`'s `--ignored` pass) cannot pass at
all — the whole Vault/OpenBao key-source suite is dead, not just failing on one assertion,
and the failure reads as an unrelated "proxy did not start listening" panic. The fix is to
emit `on_unprotected` before the key source (or to keep top-level keys ahead of every table
in the template).

**Origin**: discovered during TASK-0066 while running the QA gates for TASK-0062 and TASK-0064.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 make e2e-vault starts the proxy and vault_key_source_survives_restarts passes against a dev-mode OpenBao
- [ ] #2 The config template keeps every top-level key ahead of the first TOML table, for both key-source variants
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Already fixed on main by wave 9 (commit a690cbf, "fix(test): keep on_unprotected out of the vault key-source table") while wave 10 was running: the template now emits {on_unprotected} before {key_source}. Filed from a pre-rebase worktree, so it was a duplicate the moment it was created. No work left.
<!-- SECTION:NOTES:END -->
