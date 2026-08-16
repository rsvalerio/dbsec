---
id: TASK-0114
title: >-
  Predicates over a protected but non-searchable column are relayed with no
  warning and no refusal, silently matching no rows
status: Done
assignee: []
created_date: '2026-08-14 16:48'
updated_date: '2026-08-14 20:40'
labels:
  - code-review-rust
  - security
dependencies: []
modified_files:
  - crates/proxy/src/encrypt.rs
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**Rule**: SEC-31 (no security bypass on error; fail closed), CL-3

**File**: `crates/proxy/src/encrypt.rs:862` (`rewrite_equality`), `crates/proxy/src/encrypt.rs:831` (`rewrite_in_list`), `crates/proxy/src/encrypt.rs:1099` (`searchable_operand`)

**What**: three separate places gate the `Unprotected::Predicate` signal on `supports_search()`:

- `rewrite_equality` — `if !transform.supports_search() { return Ok(false); }`
- `rewrite_in_list` — the same guard
- `searchable_operand` — `.filter(|t| t.supports_search())`, which is what `unsupported_predicate` consults

`supports_search()` is true only for `EncryptTransform` built with an index key (`searchable = true`). It is false for `encrypt` without `searchable`, for `FpeTransform`, and for `TokenTransform` — all three of which store something that is **not** the plaintext. So `WHERE email = 'alice@example.com'` on an `encrypt` column that is not searchable is relayed byte-for-byte upstream, where it compares the client's plaintext against `DBS1 || key_id || nonce || ciphertext` and matches nothing.

Confirmed with `on_unprotected = "reject"` and a non-searchable `encrypt` column: both `WHERE email = '…'` and `WHERE email IN ('…','…')` come back as `FrameAction::Relay` — no warning, no ErrorResponse.

This contradicts the module's own stated rule (`crates/proxy/src/encrypt.rs:58`): *"Anything else that mentions a searchable column … is an `Unprotected` site rather than a silent no-op, because comparing a client's plaintext against the stored form matches no row and reads as an empty result rather than an error."* The reasoning is about the stored form differing from the plaintext, which is true of every transform — not only the searchable ones.

**Why it matters**: this is the exact failure the `Unprotected::Predicate` machinery exists to prevent, and it is the largest remaining hole in it: an operator who turns on `on_unprotected = "reject"` specifically to be told about queries that cannot work gets nothing at all for the most common column shape (`transform = "encrypt"` with the default `searchable = false`). "No rows" reads as "no such user" — a login check, an authorization lookup or a uniqueness probe silently inverts. For `fpe` and `token`, whose stored forms *are* deterministic, the query could even be made to work by sealing the compared literal, so the silence hides a fixable case as well as an unfixable one.

**Suggested direction**: route every protected column through `unprotected(&Unprotected::Predicate { .. })` when the predicate cannot be rewritten, regardless of `supports_search()`. Separately consider rewriting `col = <literal>` for the deterministic `fpe`/`token` transforms by sealing the literal, which makes those predicates correct rather than merely reported.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 An equality predicate over an encrypt column with searchable = false is an on_unprotected site: warned under warn, refused under reject
- [x] #2 The same holds for IN lists, and for fpe and token columns
- [x] #3 Mask-only columns (transform = "none") stay silent, since their stored form is the plaintext and the predicate is correct as written
- [x] #4 Tests cover each transform kind under both on_unprotected settings
<!-- AC:END -->
