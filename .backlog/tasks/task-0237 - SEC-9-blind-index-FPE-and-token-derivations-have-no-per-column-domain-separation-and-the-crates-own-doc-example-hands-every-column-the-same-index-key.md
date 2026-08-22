---
id: TASK-0237
title: >-
  SEC-9: blind index, FPE and token derivations have no per-column domain
  separation, and the crate's own doc example hands every column the same index
  key
status: Triage
assignee: []
created_date: '2026-08-21 19:50'
labels:
  - code-review-rust
  - security
dependencies: []
modified_files:
  - crates/core/src/lib.rs
  - crates/core/src/blind_index.rs
  - crates/core/src/transform.rs
  - crates/core/src/keys.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/core/src/lib.rs:27-35` (also `crates/core/src/blind_index.rs:15-20`, `crates/core/src/transform.rs:254`, `crates/core/src/transform.rs:315`, `crates/core/src/keys.rs:81-83`)

**What**: The three deterministic transforms derive their stored form from the key alone: `blind_index::compute` is `HMAC(key, plaintext)`, `FpeTransform` runs FF1 with an empty tweak (`ff1.encrypt(&[], …)`), `TokenTransform` reuses `compute`. The column name enters only as the *name* under which `KeySource::index_key` is asked for a key. Cross-column separation therefore rests entirely on the key source returning a distinct key per name, which the crate neither requires nor checks — and its front-page example (`lib.rs:34`, `StaticKeys::index_key`) returns `Key::new([3; 32])` for every name, as do the test stubs in `protector.rs`, `policy.rs` and `derive.rs`. An embedder who copies the five-minute example ships a deployment in which the token for `users.ssn = X` equals the blind index for `users.email = X`, and `cards.pan` pseudonymises under the same FF1 permutation as `cards.cvv`: equality and frequency analysis then work *across* columns and tables, not only within one, which is wider than the leak the docs declare ("equal plaintexts map to equal stored bytes" per column).

**Why it matters**: Key separation by naming convention is fine when it is enforced; here the only enforcement is prose, and the canonical example violates it. Two independent closures: (1) make the example return a per-name key (e.g. derived via HMAC from a root key, or a map keyed by column) and say why; (2) for the next stored-format major, bind the column name into the derivation (HMAC over `name || 0 || plaintext`, FF1 tweak = column name) so the property no longer depends on the key source. At minimum `Policy::build` or `Protector::new` could probe the key source for the configured names and refuse two columns that resolve to byte-identical index keys.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The lib.rs doc example and README example return a distinct key per index_key name, with a sentence explaining that one key per column is a requirement
- [ ] #2 KeySource::index_key's docs state that two names must never resolve to the same key and what breaks if they do
- [ ] #3 Either Protector::new refuses a policy whose configured columns resolve to identical index keys, or a design note records why the check is left to the key source and what the next stored-format version will bind
<!-- AC:END -->
