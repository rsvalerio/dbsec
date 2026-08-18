---
id: TASK-0096
title: No core-dump or swap hardening for a process that holds every key
status: Done
assignee:
  - TASK-0120
created_date: '2026-08-14 14:06'
updated_date: '2026-08-17 20:29'
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
- [x] #1 Core dumps are disabled by default for the running proxy, with an explicit opt-in for debugging
- [x] #2 Deployment docs cover swap/mlock guidance for the key-holding process
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Implemented in TASK-0120 (branch code-review/TASK-0120).

- New `crates/proxy/src/hardening.rs`: `disable_core_dumps()` sets `RLIMIT_CORE` to `{0, 0}` and, on Linux, clears the dumpable attribute (`prctl(PR_SET_DUMPABLE, 0)`) — the rlimit alone is ignored by a `kernel.core_pattern` piping to systemd-coredump/apport. Called from `start()` before any config or key material is read; a failure is fatal and the message names the opt-in.
- `--allow-core-dumps` is the explicit debugging opt-in (AC #1).
- The workspace `forbid(unsafe_code)` rules out a raw libc FFI, so the two syscalls go through `rustix` (safe signatures, already in the graph via tempfile, `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT`). Declared as a `[target.'cfg(unix)'.dependencies]` entry so non-unix builds are unaffected; `cargo deny check` is green.
- `mlockall` is deliberately not attempted: it would have to cover every allocation the process makes and needs an `RLIMIT_MEMLOCK` only the deployment can grant, so a partial lock would read as a guarantee it is not.
- AC #2: README gained a "Deploying the proxy" section covering the core-dump hardening and its opt-in, swap guidance (no swap, or encrypted swap, and why the proxy does not mlock), and a sample systemd unit with `LimitCORE=0`, `MemoryDenyWriteExecute`, `ProtectSystem=strict` and friends.
- Test: `disabling_core_dumps_zeroes_the_limit_and_clears_dumpable` observes both through `getrlimit` and `prctl(PR_GET_DUMPABLE)` rather than trusting the `Ok`.
<!-- SECTION:NOTES:END -->
