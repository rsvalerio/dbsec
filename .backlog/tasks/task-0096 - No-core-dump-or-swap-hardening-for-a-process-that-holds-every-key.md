---
id: TASK-0096
title: No core-dump or swap hardening for a process that holds every key
status: Triage
assignee: []
created_date: '2026-08-14 14:06'
labels:
  - security-review
  - security
dependencies: []
modified_files:
  - crates/proxy/src/main.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: process-wide — no `prctl(PR_SET_DUMPABLE, 0)`, `RLIMIT_CORE`, or `mlock` anywhere (grep-verified) in `crates/proxy/src/main.rs` startup.

**What**: the proxy holds every DEK, every deterministic index key, and the Vault token in memory but takes no standard hardening against those landing on disk.

**Why it matters**: a panic/abort under default systemd-coredump writes the full key set and the token into a core file; Drop-based zeroization never runs on abort. Swap can page the same material out. Standard hardening for a process of this sensitivity.

**Fix shape**: set `PR_SET_DUMPABLE = 0` and `RLIMIT_CORE = 0` at startup (behind a flag if a debug build wants cores), and document `mlock`/swap-off guidance; note the deployment-docs angle regardless.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Core dumps are disabled by default for the running proxy, with an explicit opt-in for debugging
- [ ] #2 Deployment docs cover swap/mlock guidance for the key-holding process
<!-- AC:END -->
