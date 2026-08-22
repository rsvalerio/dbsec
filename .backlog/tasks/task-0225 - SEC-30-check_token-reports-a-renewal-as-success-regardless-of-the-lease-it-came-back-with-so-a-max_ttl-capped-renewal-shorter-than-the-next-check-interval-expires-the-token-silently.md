---
id: TASK-0225
title: >-
  SEC-30: check_token reports a renewal as success regardless of the lease it
  came back with, so a max_ttl-capped renewal shorter than the next check
  interval expires the token silently
status: Triage
assignee: []
created_date: '2026-08-21 19:49'
labels:
  - code-review-rust
  - security
dependencies: []
modified_files:
  - crates/vault/src/source.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/vault/src/source.rs:715` (also `crates/vault/src/source.rs:745`, `crates/vault/src/source.rs:101`)

**What**: `check_token` branches on the *pre*-renewal status only. When `ttl <= TOKEN_RENEW_THRESHOLD` and the token is renewable it calls `renew_token`, logs `"renewed the vault token"` at INFO with whatever `lease_duration` came back, and returns `TokenCheck::Renewed` — without looking at that returned TTL. Vault caps `renew-self` at the token's `max_ttl` (or the mount's `max_lease_ttl`): as a token approaches that ceiling each renewal succeeds but hands back a shrinking lease (600s, then 300s, then 45s, ...), and once the ceiling is reached `renew-self` fails. With `TOKEN_CHECK_INTERVAL = 60s`, a renewal that returns `lease_duration < 60` is reported at INFO as healthy and the token is dead before the next pass runs; the operator-facing WARN ("issue a fresh token and restart") that this watch exists to produce is never emitted, because the *failing* renewal happens after the token already expired and `token_status` then returns 403 -> `TokenCheck::Unknown` ("Not evidence the token is bad"). Secondary: `token_watch` sleeps `TOKEN_CHECK_INTERVAL` *before* its first check, so a token that `connect` succeeded with but that has under 60s of lease left is never inspected.

**Why it matters**: SEC-30 asks for key/secret expiry to be surfaced, and the module doc promises exactly that: "When the lease is running out and cannot be extended, the watch says so at WARN on every check rather than waiting for the failure". The max_ttl ceiling is the normal way a renewable token ends, so the path that is silent is the common one, not an edge. The fix is local: treat a post-renewal TTL that is still at or under the threshold (or under the check interval) as `Expiring` and WARN with the returned lease, and run the first check immediately rather than after one interval.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 check_token inspects the TTL returned by renew_token: a renewal that leaves the lease at or below TOKEN_RENEW_THRESHOLD (or below TOKEN_CHECK_INTERVAL) returns TokenCheck::Expiring and logs at WARN naming the remaining lease
- [ ] #2 token_watch performs its first check without waiting one TOKEN_CHECK_INTERVAL (or the threshold/interval relationship is documented as guaranteeing at least one check before expiry)
- [ ] #3 A FakeStore test where renews_to has ttl < TOKEN_CHECK_INTERVAL asserts Expiring and a WARN event, not Renewed
<!-- AC:END -->
