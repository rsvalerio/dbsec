---
id: TASK-0079
title: >-
  ERR-5: process-wide key caches panic forever on a poisoned lock while session
  state deliberately recovers
status: Done
assignee:
  - TASK-0126
created_date: '2026-08-14 12:34'
updated_date: '2026-08-18 09:43'
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
- [x] #1 No lock acquisition in Ciphers or VaultKeySource can panic on poison; each site documents why the value is intact
- [x] #2 The workspace has one poison policy, not two
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
New crates/core/src/sync.rs holds the workspace poison policy as one Unpoisoned extension trait, documented once. All 5 Ciphers sites (crates/core/src/envelope.rs) and all 6 VaultKeySource sites (crates/proxy/src/vault.rs) now recover instead of .expect(...); rows.rs, portal.rs and the main.rs log-capture helper were converted off their hand-rolled unwrap_or_else(PoisonError::into_inner) onto the same helper, so there is a single definition of the policy. AC #1 substitution: rather than repeating a justification at each of the 11 call sites, the reasoning lives in the crate::sync module doc with a pointer at each of the two impls (Ciphers::active, impl KeySource for VaultKeySource). New tests: sync::tests::a_poisoned_lock_still_hands_back_its_value and envelope::tests::a_poisoned_cache_keeps_serving (poisons both process-wide caches from a panicking thread and proves seal/open keep working).
<!-- SECTION:NOTES:END -->
