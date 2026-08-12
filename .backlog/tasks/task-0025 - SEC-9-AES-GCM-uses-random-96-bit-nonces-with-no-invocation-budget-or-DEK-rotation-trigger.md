---
id: TASK-0025
title: >-
  SEC-9: AES-GCM uses random 96-bit nonces with no invocation budget or DEK
  rotation trigger
status: To Do
assignee:
  - TASK-0054
created_date: '2026-08-11 19:23'
updated_date: '2026-08-11 22:42'
labels:
  - code-review-rust
  - security
  - crypto
dependencies: []
modified_files:
  - crates/core/src/envelope.rs
  - crates/core/src/keys.rs
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/core/src/envelope.rs:28-43`, `crates/core/src/keys.rs:16-24`

**What**: `envelope::encrypt` draws a fresh 12-byte nonce per call and never records how many times the active DEK has been used:

```rust
let mut nonce = [0u8; NONCE_LEN];
rand::thread_rng().fill_bytes(&mut nonce);
```

`KeySource::active_key` hands out the same DEK indefinitely — there is no counter, no expiry, no "this key is exhausted" error, and nothing in `FileKeySource` or the trait that could carry one.

**Why it matters**: With random IVs, AES-GCM's security argument depends on an invocation limit. NIST SP 800-38D §8.3 caps a random-IV key at 2^32 invocations so the nonce-collision probability stays below 2^-32; a repeated nonce under one key leaks the XOR of two plaintexts and, worse, the GHASH authentication subkey, which lets an attacker forge ciphertexts for that key.

2^32 is reachable here. This encrypts once per protected column value per write, not once per connection or per session — a table with three protected columns at a modest 10k inserts/sec crosses 2^32 in under two days. The failure is silent: nothing in the code notices, and the damage is retroactive across every row stored under that DEK.

Options, roughly in order of cost:

- Cheapest correct fix: extend `KeySource` with a per-key invocation budget so the active DEK is retired (error, or automatic roll to a new DEK) before the limit. The envelope already stamps `key_id`, so the read path handles multiple live DEKs today — this is a write-path policy change only.
- Alternatively switch the nonce to a deterministic construction (a per-key counter, or a random 4-byte prefix plus an 8-byte counter per SP 800-38D §8.2.1), which removes the birthday bound entirely but needs durable counter state across restarts.
- Or use an extended-nonce / nonce-misuse-resistant AEAD (XChaCha20-Poly1305, or AES-GCM-SIV) where a 192-bit random nonce makes collision negligible without any bookkeeping.

Whichever is chosen, the limit and the reasoning belong in a comment at the encrypt callsite and in `plans/PLAN.md` next to the existing crypto caveats. Related but distinct: TASK-0003 covers rotation of the *deterministic* keys (blind index, FPE, token), which cannot rotate by design; this is about the AEAD DEK, which can.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A documented nonce-safety strategy is in place: either a per-DEK invocation budget that retires the key before the random-nonce limit, a counter-based nonce, or a nonce-misuse-resistant AEAD
- [ ] #2 The chosen limit and its basis (NIST SP 800-38D or equivalent) are recorded in a comment at the encrypt path and in plans/PLAN.md
- [ ] #3 If a budget is used, exhausting it produces a clear error or an automatic key roll rather than continuing to encrypt
- [ ] #4 A test covers the behaviour at the budget boundary
<!-- AC:END -->
