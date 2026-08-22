---
id: TASK-0198
title: >-
  CONC-1: Ciphers::active takes an RwLock read on every seal for a whole-value
  slot that is replaced only on DEK roll
status: Triage
assignee: []
created_date: '2026-08-21 19:31'
labels:
  - code-review-rust
  - concurrency
dependencies: []
modified_files:
  - crates/core/src/envelope.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/core/src/envelope.rs:470` (also `crates/core/src/envelope.rs:521-530`)

**What**: `active: RwLock<Option<(KeyId, Arc<Cipher>)>>` is read on every `Ciphers::seal` (the hot path: once per protected value) and written only once at first use and once per budget exhaustion (every 2^32 encryptions). This is the read-mostly whole-value shape CONC-1 calls out: every writer-free reader still pays the `RwLock` reader-count RMW on a shared cache line, which is the contention point under a multi-thread tokio runtime sealing in parallel. `arc_swap::ArcSwapOption<(KeyId, Arc<Cipher>)>` gives lock-free `load()` for readers and an atomic `store()` for the roll path, and the roll's "another thread may have rolled already" check becomes a `compare_and_swap` on the previous `Arc`. `by_id` (read per open) is a map, so it stays as is or moves with the same crate's `ArcSwap<HashMap>` copy-on-write pattern.

**Why it matters**: Performance under contention on the data path of a proxy; correctness is unaffected. The crate keeps a deliberately small dependency set, so this is a judgement call — `arc-swap` is tiny and widely used, but if the maintainers would rather not add it, a documented decision closes this finding.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Ciphers::seal reads the active DEK slot without taking a lock (ArcSwap or equivalent), with the roll path still guaranteeing a single fresh cipher per key id
- [ ] #2 The existing roll, exhaustion and poisoned-cache tests pass (or the poisoned-cache test is adapted if the slot no longer has a lock to poison)
- [ ] #3 Or: a short comment on the field records the decision to keep RwLock and why
<!-- AC:END -->
