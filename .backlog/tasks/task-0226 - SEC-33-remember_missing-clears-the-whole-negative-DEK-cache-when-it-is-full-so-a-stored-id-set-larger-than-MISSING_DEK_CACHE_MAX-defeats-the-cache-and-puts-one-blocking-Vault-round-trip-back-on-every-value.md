---
id: TASK-0226
title: >-
  SEC-33: remember_missing clears the whole negative DEK cache when it is full,
  so a stored id set larger than MISSING_DEK_CACHE_MAX defeats the cache and
  puts one blocking Vault round-trip back on every value
status: Triage
assignee: []
created_date: '2026-08-21 19:49'
labels:
  - code-review-rust
  - security
  - performance
dependencies: []
modified_files:
  - crates/vault/src/source.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/vault/src/source.rs:680` (also `crates/vault/src/source.rs:670`, `crates/vault/src/source.rs:772`)

**What**: `remember_missing` runs `retain` over the whole map on every miss and then, at `MISSING_DEK_CACHE_MAX` (4096) live entries, calls `missing.clear()` — every known-absent id is forgotten at once, including the ones a result set is about to hit again on the next row. The key id comes out of stored envelopes (the doc comment says so), so whoever can write rows — a compromised application, a migration that copied envelopes from another deployment, or simply a table with more than 4096 distinct lost DEK ids — controls how often the cache is flushed. Each flushed id costs a `block_in_place` Vault round-trip (up to `timeout_secs`) per value, which is precisely the per-value amplification the cache was added to prevent. Also: `recently_missing` (read lock) and `remember_missing` (write lock) are separate critical sections, so concurrent misses for the same id all fetch (already tracked as TASK-0209), and nothing tests the bound or the TTL expiry.

**Why it matters**: SEC-33 / PERF-16 — a bounded cache whose eviction is "drop everything" has a cliff instead of a degradation, and the cliff is reachable from data rather than config. Evicting the oldest entry (or a random one, or a fixed fraction) keeps the steady-state hit rate under an adversarial id set; a sorted-by-`Instant` structure or a simple "evict the entry with the smallest `seen`" on insert is enough at this size.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Reaching MISSING_DEK_CACHE_MAX evicts one or a bounded fraction of entries (oldest first), never the whole map
- [ ] #2 A test inserts MISSING_DEK_CACHE_MAX + 1 distinct ids and asserts the most recent ones are still negatively cached (dek_reads does not grow on re-lookup)
- [ ] #3 A test covers TTL expiry of a negative entry (e.g. by making the TTL injectable or using a shorter test constant)
<!-- AC:END -->
