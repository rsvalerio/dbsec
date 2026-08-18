---
id: TASK-0112
title: >-
  The canonical upsert DO UPDATE SET col = EXCLUDED.col is falsely refused under
  reject mode
status: Done
assignee:
  - TASK-0121
created_date: '2026-08-14 18:16'
updated_date: '2026-08-17 20:28'
labels:
  - security-review
  - availability
  - sql-rewrite
dependencies: []
modified_files:
  - crates/proxy/src/encrypt.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/encrypt.rs:896` (`seal_expr`).

**What**: `SET email = EXCLUDED.email` (and `UPDATE ... SET email = other_already_sealed_col`) is a `CompoundIdentifier`, so `literal_plaintext` returns `None` and the code raises `Unprotected::UnsupportedValue`. But `EXCLUDED.email` is exactly the value the proxy already sealed in the `VALUES` clause of the same statement — storing it is correct and safe.

**Why it matters**: under `on_unprotected = "reject"` the standard PostgreSQL upsert idiom `INSERT ... ON CONFLICT (id) DO UPDATE SET email = EXCLUDED.email` is refused outright. There is no plaintext exposure — this is an availability / usability false positive, but it is exactly the kind of "correct SQL that reject breaks" that pushes operators to stay on the permissive `warn` default instead of enabling `reject`, which weakens the whole product's fail-closed story.

**Fix shape**: recognise `EXCLUDED.<col>` (and a same-row reference to another already-protected column of the same transform) as a safe value that passes through without sealing and without an `unprotected()` refusal. Be careful to only whitelist references that are provably already-sealed (the `EXCLUDED` pseudo-relation of the same INSERT, whose corresponding VALUES element the proxy sealed), not arbitrary column expressions.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 `INSERT ... ON CONFLICT DO UPDATE SET protected = EXCLUDED.protected` is accepted (not refused) under `reject`
- [x] #2 The whitelist is limited to provably-already-sealed references and does not admit arbitrary column expressions
- [x] #3 A test asserts the canonical upsert idiom passes under both `warn` and `reject`
<!-- AC:END -->
