---
id: TASK-0097
title: >-
  thread_rng GCM nonces are fork-unsafe and the code's rationale for accepting
  thread_rng does not cover fork
status: Triage
assignee: []
created_date: '2026-08-14 14:06'
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
- [ ] #1 The nonce rationale addresses the fork hazard explicitly
- [ ] #2 If a forking deployment is supported, nonce generation is fork-safe
<!-- AC:END -->
