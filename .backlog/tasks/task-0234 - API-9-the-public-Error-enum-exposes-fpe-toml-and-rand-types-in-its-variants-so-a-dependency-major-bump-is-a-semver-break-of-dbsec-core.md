---
id: TASK-0234
title: >-
  API-9: the public Error enum exposes fpe, toml and rand types in its variants,
  so a dependency major bump is a semver break of dbsec-core
status: Triage
assignee: []
created_date: '2026-08-21 19:50'
labels:
  - code-review-rust
  - api-design
dependencies: []
modified_files:
  - crates/core/src/lib.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/core/src/lib.rs:225-227` (also `crates/core/src/lib.rs:249-257`, `crates/core/src/lib.rs:283-284`)

**What**: Three `Error` variants carry third-party types in their public shape: `Fpe(#[from] fpe::ff1::NumeralStringError)`, `KeyFileParse { source: toml::de::Error }` and `Entropy(#[from] rand::Error)`. `fpe` is at 0.6, `toml` at 0.8 and `rand` at 0.8 — all pre-1.0, where every minor is a breaking release — and none of them is re-exported, so a downstream crate that matches on these variants or names the payload type must depend on the exact same version. `rand::Error` was removed outright in rand 0.9, so the planned `rand` upgrade (SEC-10 guidance in the rules names the 0.10 API) is a public-API change for this crate rather than an internal one. The `#[from]` on two of them also means a `?` anywhere in the crate can widen the variant's meaning without review.

**Why it matters**: dbsec-core is published and states a semver policy in lib.rs; leaking pre-1.0 dependency types into the public error surface ties the crate's major version to three other crates' release cadence. Either box the cause behind `Box<dyn Error + Send + Sync>` (as `KeyBackend` already does), keep the typed cause private behind an accessor, or re-export the types and document the coupling.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 No Error variant's public shape names a type from a pre-1.0 dependency, or each such type is re-exported from dbsec-core and the coupling is documented in the Compatibility section
- [ ] #2 Error::source() still reaches the original fpe / toml / rand error for every affected variant
<!-- AC:END -->
