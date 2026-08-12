---
id: TASK-0028
title: >-
  PERF-3: every transformed value re-runs a key lookup, a key clone and a full
  AES key schedule
status: To Do
assignee:
  - TASK-0054
created_date: '2026-08-11 19:24'
updated_date: '2026-08-11 22:42'
labels:
  - code-review-rust
  - performance
dependencies: []
modified_files:
  - crates/core/src/transform.rs
  - crates/core/src/envelope.rs
  - crates/core/src/keys.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/core/src/transform.rs:145-147`, `crates/core/src/envelope.rs:29`, `crates/core/src/envelope.rs:61`, `crates/core/src/keys.rs:104-116`

**What**: The per-value path rebuilds all of its cryptographic state from scratch on every call. Nothing is cached across values, rows, or connections.

- `transform.rs:145-147` — `FpeTransform::transform_digits` calls `self.keys.index_key(&self.key_name)?` (a `HashMap` lookup keyed by `String`, plus a `Zeroizing<[u8; 32]>` clone) and then `FF1::<Aes256>::new(key.as_ref(), 10)`, which runs the full AES-256 key expansion. Both happen on every single value, on both the seal and open paths.
- `envelope.rs:29` and `envelope.rs:61` — `Aes256Gcm::new(key.into())` per encrypt and per decrypt: another AES-256 key schedule, plus GHASH subkey derivation.
- `keys.rs:104-116` — every `active_key`/`key`/`index_key` call clones the key out of the map. `transform.rs:194` (`TokenTransform::seal`) does the same lookup-and-clone per value.
- `transform.rs:83-89` — `EncryptTransform::seal` compounds it: one `active_key()` and one `index_key()` lookup-and-clone per value for a searchable column.

**Why it matters**: This is the hottest path in the product. It runs once per protected column per row, so a `SELECT` returning 10k rows across three protected columns runs 30k key schedules and 30k key clones on top of 30k actual decryptions. AES-256 key expansion is roughly comparable in cost to encrypting a small value, so for the short values this crate targets — emails, card numbers, SSNs — setup can plausibly dominate the real work. That is throughput left on the floor for no design benefit.

The state is trivially cacheable because it depends only on the key, which is fixed for the lifetime of a transform in the common case:

- `FpeTransform` can build its `FF1` instance once and hold it, or memoize on key id.
- `EncryptTransform` can hold an `Aes256Gcm` per key id rather than per call — the read path needs a small map since old key ids stay live, but the write path needs exactly one.
- `KeySource` returning `Arc<Key>` instead of a cloned `Key` removes the per-call copy, and has the side benefit of not scattering additional copies of key material across the heap (see TASK-0024).

Any caching here interacts with the DEK invocation budget in TASK-0025 and with rotation, so those two are worth designing together. Worth benchmarking before and after — the claim above is a cost model, not a measurement, and the fix should be justified by numbers.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Cipher state (FF1 instance, AES-GCM instance) is constructed once per key rather than once per value
- [ ] #2 Key lookup no longer clones the key material on every value; keys are shared (for example via Arc) or the cipher holding them is cached
- [ ] #3 A benchmark or measurement records seal/open throughput before and after, so the change is justified by numbers
- [ ] #4 Caching is compatible with multiple live key ids on the read path and with whatever rotation policy TASK-0025 lands
<!-- AC:END -->
