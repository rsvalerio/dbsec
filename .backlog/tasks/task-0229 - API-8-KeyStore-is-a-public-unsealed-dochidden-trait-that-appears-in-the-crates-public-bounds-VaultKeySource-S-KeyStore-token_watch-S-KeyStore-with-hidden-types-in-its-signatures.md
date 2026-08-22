---
id: TASK-0229
title: >-
  API-8: KeyStore is a public, unsealed #[doc(hidden)] trait that appears in the
  crate's public bounds (VaultKeySource<S: KeyStore>, token_watch<S: KeyStore>)
  with hidden types in its signatures
status: Triage
assignee: []
created_date: '2026-08-21 19:50'
labels:
  - code-review-rust
  - api
dependencies: []
modified_files:
  - crates/vault/src/source.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/vault/src/source.rs:222` (also `crates/vault/src/source.rs:130`, `crates/vault/src/source.rs:186`, `crates/vault/src/source.rs:257`, `crates/vault/src/source.rs:272`, `crates/vault/src/source.rs:745`, `crates/vault/src/source.rs:760`)

**What**: `KeyStore`, `IndexKeyRecord`, `LegacyIndexKeys`, `TokenStatus` and `TokenCheck` are `pub` + `#[doc(hidden)]` "testing seams; not API", but they are reachable and implementable by any downstream crate: `pub struct VaultKeySource<S = VaultStore>` and `pub async fn token_watch<S: KeyStore>` put the trait in the public signature, the trait has no sealing supertrait, and its methods take/return the hidden types (`IndexKeyRecord` has private fields and no constructor, so an external impl can only return `None`). `doc(hidden)` hides the items from rustdoc but not from semver: adding a method to `KeyStore`, changing `TokenStatus`'s fields, or renaming `TokenCheck` variants is a breaking change for anyone who took the hidden path, and `cargo semver-checks` will flag it. There are also two public ways to run the watch (`source::token_watch(arc, fut)` and `Arc<VaultKeySource>::token_watch(fut)`) for one job.

**Why it matters**: API-8 — a trait the crate wants to keep evolving must be sealed (`pub trait KeyStore: private::Sealed`) so the only implementors are `VaultStore` and the in-crate fake; that makes `doc(hidden)` a documentation choice rather than a semver promise the crate cannot keep. Alternatively make the generic parameter non-public: `pub struct VaultKeySource(Inner<VaultStore>)` with the generic inner type `pub(crate)`, which also removes the need for `IndexKeyRecord`/`LegacyIndexKeys`/`TokenStatus`/`TokenCheck` to be `pub` at all.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 KeyStore is sealed (private supertrait) or no longer appears in any public signature; IndexKeyRecord, LegacyIndexKeys, TokenStatus and TokenCheck are pub(crate)
- [ ] #2 Exactly one public way to drive the token watch is kept (the other is removed or #[deprecated])
- [ ] #3 cargo doc --no-deps -p dbsec-vault shows no hidden types in public signatures; existing tests compile against the in-crate seam
<!-- AC:END -->
