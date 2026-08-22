---
id: TASK-0271
title: >-
  ARCH-11: crates/proxy/Cargo.toml declares rustls-pki-types as a direct
  dependency nothing in the proxy uses, and pins rcgen outside
  [workspace.dependencies]
status: Triage
assignee: []
created_date: '2026-08-22 00:38'
labels:
  - code-review-rust
  - architecture
dependencies: []
modified_files:
  - crates/proxy/Cargo.toml
  - Cargo.toml
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/Cargo.toml:19`

**What**: crates/proxy/Cargo.toml:19 lists `rustls-pki-types = { workspace = true }`, but no file under crates/proxy/src or crates/proxy/tests references the `rustls_pki_types` crate — every use goes through rustls' re-export (`rustls::pki_types::...`, tls.rs:14-15, session.rs, tests/common/mod.rs). Separately, crates/proxy/Cargo.toml:47 pins `rcgen = "0.13"` directly, while the workspace's stated policy (Done TASK-0034 for `tempfile`, open TASK-0203 for `sqlx`) is that every dependency is declared in `[workspace.dependencies]` and inherited.

**Why it matters**: An unused direct dependency is an extra line in `cargo audit`/`cargo deny` output and a version requirement that can drift from what rustls actually resolves; a dev-dependency pinned outside the workspace table is the drift the ARCH-11 policy exists to prevent.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 `rustls-pki-types` is removed from crates/proxy/Cargo.toml (and from `[workspace.dependencies]` if no other member uses it), and the proxy still builds and tests
- [ ] #2 `rcgen` is declared in `[workspace.dependencies]` and inherited with `{ workspace = true }` in the proxy's dev-dependencies
- [ ] #3 `cargo machete` (or equivalent) reports no unused dependencies for crates/proxy
<!-- AC:END -->
