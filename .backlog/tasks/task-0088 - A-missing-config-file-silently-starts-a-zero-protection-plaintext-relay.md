---
id: TASK-0088
title: A missing config file silently starts a zero-protection plaintext relay
status: Triage
assignee: []
created_date: '2026-08-14 14:06'
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
- [ ] #1 Starting with no argument and no dbsec.toml present refuses to run unless an explicit plaintext-relay opt-in is set
- [ ] #2 The refusal message names the missing config and the opt-in flag
- [ ] #3 A CLI test covers the no-config, no-flag case
<!-- AC:END -->
