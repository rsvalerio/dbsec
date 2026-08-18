---
id: TASK-0097
title: >-
  thread_rng GCM nonces are fork-unsafe and the code's rationale for accepting
  thread_rng does not cover fork
status: Done
assignee:
  - TASK-0118
created_date: '2026-08-14 14:06'
updated_date: '2026-08-17 20:33'
labels:
  - security-review
  - crypto
dependencies: []
modified_files:
  - crates/core/src/envelope.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/core/src/envelope.rs:94-95` (`thread_rng().fill_bytes` for the GCM nonce), rationale at `:84-93`.

**What**: the nonce comment dismisses `ThreadRng`'s fork hazard by pointing at `MAX_ENCRYPTIONS_PER_KEY`, but that bound does not protect against fork: two processes that fork *after* the DEK is cached inherit identical ChaCha12 thread-local state and emit the same 96-bit nonce stream, each staying under budget while colliding nonce-for-nonce under one DEK.

**Why it matters**: latent today — `main` builds a multi-thread tokio runtime and does not fork. But if dbsec is ever run under a pre-forking supervisor that forks after `Ciphers` resolves the active DEK, both children reuse nonces under one key: GCM nonce reuse -> plaintext-XOR recovery and GHASH forgery, retroactive over every row under that DEK. The comment's reasoning should not be relied on if the deployment model changes.

**Fix shape**: correct the rationale to address fork, and/or reseed/route nonces through a fork-safe source (or `OsRng`) if a forking model is ever supported.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 The nonce rationale addresses the fork hazard explicitly
- [x] #2 If a forking deployment is supported, nonce generation is fork-safe
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Fixed in wave TASK-0118 (documentation fix — the code's nonce source is unchanged and correct for the supported deployment model).

AC #1: the rationale on the nonce draw in `Cipher::encrypt` now separates the two hazards explicitly — birthday collisions *within* one generator's stream (what `MAX_ENCRYPTIONS_PER_KEY` bounds) from two generators emitting the *same* stream (what the budget does nothing about). It names `fork()` after DEK resolution as the way to reach the second, states the consequence (identical ChaCha12 state, nonce-for-nonce collision under one key, plaintext XOR + GHASH subkey leak retroactive over every row), and says what supporting a forking model would take. Echoed in the `envelope` module docs so it is discoverable without reading the function.

AC #2: a forking deployment is *not* supported, so the conditional does not fire. Rather than leave that implicit, it is now a stated constraint in three places an operator reads: the module docs, the PLAN caveats (with the two fixes a forking model would need — reseed after fork, or `OsRng` at one `getrandom` per value), and a "do not run the proxy under a pre-forking supervisor" paragraph in the README's operating section.
<!-- SECTION:NOTES:END -->
