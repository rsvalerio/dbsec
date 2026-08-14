---
id: TASK-0079
title: >-
  ERR-5: process-wide key caches panic forever on a poisoned lock while session
  state deliberately recovers
status: Triage
assignee: []
created_date: '2026-08-14 12:34'
labels:
  - code-review-rust
  - error-handling
  - concurrency
dependencies: []
modified_files:
  - crates/core/src/envelope.rs
  - crates/proxy/src/vault.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/core/src/envelope.rs:182` (and 4 sibling sites in `Ciphers`), `crates/proxy/src/vault.rs:462` (and 5 sibling `expect("lock")` sites in `VaultKeySource`)

**What**: the workspace has two documented poison policies. `rows.rs` and `portal.rs`
recover with `unwrap_or_else(PoisonError::into_inner)`, each with a comment proving the
guarded value is structurally intact ("refusing to read it would turn one task's bug into
a second panic"). `envelope::Ciphers` and `VaultKeySource` — the *process-wide* caches —
instead `.expect("ciphers lock")` / `.expect("lock")` on poison.

**Why it matters**: the asymmetry is exactly backwards. A poisoned session-local lock
costs one session; a poisoned process-wide lock under `.expect` costs every session from
then on — each new session panics in its task (caught by the JoinSet, logged
"terminated abnormally"), so the proxy stays up, accepts connections, and fails 100% of
them until restarted. The same intact-value argument the session modules document applies
here: every critical section is a single map/slot operation on `Zeroizing` keys, `Arc`s
and `Instant`s, so the guarded state cannot be left half-updated. The panic is close to
unreachable today (nothing in those critical sections panics), which is why this is Low —
but the failure mode if it ever fires is a silent full outage, and the fix is mechanical.

**Fix shape**: `unwrap_or_else(PoisonError::into_inner)` with the same one-line
justification the session modules carry, or a helper shared by both crates.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 No lock acquisition in Ciphers or VaultKeySource can panic on poison; each site documents why the value is intact
- [ ] #2 The workspace has one poison policy, not two
<!-- AC:END -->
