---
id: TASK-0227
title: >-
  CONC-1: KeySource::key and index_key take a std RwLock read and clone a Key on
  every protected value, for caches that are written only on a cache miss
status: Triage
assignee: []
created_date: '2026-08-21 19:49'
labels:
  - code-review-rust
  - concurrency
  - performance
dependencies: []
modified_files:
  - crates/vault/src/source.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/vault/src/source.rs:772` (also `crates/vault/src/source.rs:788`, `crates/vault/src/source.rs:537`)

**What**: `deks: RwLock<HashMap<KeyId, Key>>` and `index_keys: RwLock<HashMap<String, Key>>` are read-locked on every `key()` / `index_key()` call — i.e. once per encrypted cell on the relay path, from every session thread — while they are written only when a new DEK id or column is first seen (a handful of times per process). `std::sync::RwLock` readers still contend on a shared atomic, so under a multi-thread runtime with many sessions decrypting the same column this is a cache-line bounce per value for a map whose contents are effectively immutable after warm-up. The same shape in `dbsec-core` is already tracked as TASK-0198 for `Ciphers::active`; this is the vault-side instance. `active_key` avoids the lock correctly.

**Why it matters**: CONC-1 — read-dominant, rarely-written shared state is the case for a copy-on-write snapshot (`arc_swap::ArcSwap<HashMap<..>>`, or `RwLock<Arc<HashMap>>` where the read path clones the `Arc` once and finishes without the lock) or a concurrent map (`dashmap`), not a lock taken per lookup. Low because the lookup is cheap relative to AES-GCM and the caches are small, but it sits on the per-value hot path.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The cache-hit path of key() and index_key() takes no RwLock (snapshot swap or a concurrent map), or a benchmark/comment documents that the lock is not measurable against the AES cost
- [ ] #2 Existing FakeStore tests (fetched_dek_is_cached, missing_dek_is_negatively_cached) still pass unchanged
<!-- AC:END -->
