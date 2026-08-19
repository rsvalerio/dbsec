---
id: TASK-0186
title: >-
  TEST: the other log-capture tests can silently lose events to tracing's
  callsite interest cache
status: Triage
assignee: []
created_date: '2026-08-19 10:10'
labels:
  - code-review-rust
  - test-quality
dependencies: []
modified_files:
  - crates/proxy/src/encrypt/mod.rs
  - crates/proxy/src/vault.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/encrypt/mod.rs:3193`, `crates/proxy/src/encrypt/mod.rs:3255`, `crates/proxy/src/vault.rs:1052`

**What**: `tracing` fixes a callsite's interest the first time it is hit, using whatever
subscriber the *hitting thread* has. A warning first emitted by another test's thread —
which has no subscriber — caches "nobody is listening", and every later event from that
callsite is dropped, including one emitted inside a `with_default` capture on another
thread. `no_event_from_the_write_path_carries_a_plaintext_value` hit this while TASK-0161
was being fixed: the test passed alone and failed deterministically under `cargo test`,
because a concurrent test reached the site first. It was fixed there by driving the sites
once to register the callsites, then calling
`tracing::callsite::rebuild_interest_cache()` inside the capturing subscriber before the
pass that is read.

The three capture tests above are the same shape and carry the same hazard. They pass
today only because nothing else happens to reach their callsites first; the failure mode
is a test that fails for a reason unrelated to what it asserts, or one that stops
asserting anything if its `contains` checks are ever inverted.

**Why it matters**: these tests are the only mechanical guard on what the proxy's logs
carry — the plaintext-disclosure test among them. A guard that can be silently disarmed
by unrelated test scheduling is not a guard. The fix wants to be one shared helper
(prime, rebuild, capture) that all four use, rather than the trick open-coded in one.

**Origin**: discovered during TASK-0181 while fixing TASK-0161.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The three remaining log-capture tests cannot lose an event to a callsite another thread registered first
- [ ] #2 The priming/rebuild step lives in one shared test helper rather than being open-coded per test
<!-- AC:END -->
