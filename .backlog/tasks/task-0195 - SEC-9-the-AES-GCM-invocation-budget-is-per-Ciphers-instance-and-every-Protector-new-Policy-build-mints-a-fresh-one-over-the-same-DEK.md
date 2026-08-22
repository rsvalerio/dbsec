---
id: TASK-0195
title: >-
  SEC-9: the AES-GCM invocation budget is per Ciphers instance, and every
  Protector::new / Policy::build mints a fresh one over the same DEK
status: Triage
assignee: []
created_date: '2026-08-21 19:31'
labels:
  - code-review-rust
  - security
dependencies: []
modified_files:
  - crates/core/src/policy.rs
  - crates/core/src/protector.rs
  - crates/core/src/envelope.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/core/src/policy.rs:401` (also `crates/core/src/protector.rs:116`, `crates/core/src/envelope.rs:464`)

**What**: `MAX_ENCRYPTIONS_PER_KEY` is enforced by `Cipher.used`, which lives inside the `Ciphers` cache. `Policy::build` constructs `Arc::new(Ciphers::new(keys.clone()))` on every call, with a comment explaining that one cache per process is what keeps N columns from spending N × the budget. But `Protector::new` calls `build`, so every `Protector` an application creates holds its own counter for the same active DEK. With `#[derive(Protect)]` the natural shape is one `Protector` per record type (the crate's own `tests/derive.rs` builds `Protector::new(Readable::policy(), …)`, `Protector::new(Event::policy(), …)` and a merged one side by side), so an embedder with ten record types has ten independent 2^32 budgets over one key and nothing notices. The library exposes no way to share a `Ciphers` between protectors, and the README / module docs do not say "build exactly one".

**Why it matters**: The budget exists because a repeated random nonce under one key leaks the XOR of two plaintexts and the GHASH subkey retroactively over every row stored under that DEK (envelope.rs module docs). The bound is enforced, per the docs, "not merely documented" — but only per instance, so the guarantee silently degrades with the number of `Protector`s in the process.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Two Protectors (or two Policy::build calls) over the same KeySource share one invocation counter per DEK, or the API makes sharing the Ciphers explicit and required (e.g. Protector::with_ciphers / Policy::build taking an Arc<Ciphers>)
- [ ] #2 A test builds two Protectors over one key source with a small budget and shows the combined seals fail closed / roll at the budget, not at 2 × the budget
- [ ] #3 The crate docs state the one-cache-per-DEK requirement where an embedder building several Protectors will see it
<!-- AC:END -->
