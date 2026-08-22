---
id: TASK-0209
title: >-
  PERF-16: concurrent cache misses for the same DEK id or index key name each
  issue their own blocking Vault round-trip
status: Triage
assignee: []
created_date: '2026-08-21 19:36'
labels:
  - code-review-rust
  - performance
dependencies: []
modified_files:
  - crates/vault/src/source.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/vault/src/source.rs:776` (also `crates/vault/src/source.rs:791`)

**What**: `KeySource::key` and `KeySource::index_key` do read-lock → miss → `block_on(fetch)` → write-lock insert, with nothing coalescing in-flight lookups. When N sessions touch the same old DEK id (one result set fanned out across connections) or the same column's index key on a cold start, all N miss together and each parks its own runtime worker in `block_in_place` for a full round-trip — up to `timeout_secs` each when Vault is slow. For index keys this also means N racing `create_index_key` calls; CAS makes that safe, but each loser pays a create plus a re-read.

**Why it matters**: PERF-16 names "no answer for concurrent misses" as a cache defect. Here the miss path is the expensive, worker-blocking one, so a stampede multiplies exactly the cost the module docs worry about (a hung Vault parking workers). A per-key in-flight guard (e.g. a `Mutex<HashMap<K, Arc<OnceLock<..>>>>` / single-flight map, or a write-lock-then-recheck before fetching) bounds it to one round-trip per key.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Concurrent misses for the same DEK id issue exactly one fetch_dek call (test with a FakeStore that blocks until released and counts reads)
- [ ] #2 Concurrent misses for the same index key name issue one read/create sequence
- [ ] #3 The single-flight guard never holds a std lock across the blocking fetch for unrelated keys
<!-- AC:END -->
