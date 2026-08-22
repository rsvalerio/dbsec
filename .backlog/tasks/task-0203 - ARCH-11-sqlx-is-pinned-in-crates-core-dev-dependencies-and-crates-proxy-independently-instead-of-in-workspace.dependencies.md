---
id: TASK-0203
title: >-
  ARCH-11: sqlx is pinned in crates/core dev-dependencies and crates/proxy
  independently instead of in [workspace.dependencies]
status: Triage
assignee: []
created_date: '2026-08-21 19:31'
labels:
  - code-review-rust
  - architecture
dependencies: []
modified_files:
  - crates/core/Cargo.toml
  - crates/proxy/Cargo.toml
  - Cargo.toml
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/core/Cargo.toml:52` (also `crates/proxy/Cargo.toml:48`)

**What**: Both manifests declare `sqlx = { version = "0.9.0", default-features = false, features = [...] }` directly; the core one adds `"derive"`. The workspace already centralises every other shared dependency under `[workspace.dependencies]` with `workspace = true` inheritance (TASK-0034 moved `tempfile` there for the same reason), so this is the same drift reintroduced for a heavier crate: a bump in one manifest and not the other silently builds two sqlx versions into the e2e matrix.

**Why it matters**: Version drift between the example the README points at and the proxy's driver matrix would go unnoticed until the two disagree on a wire behaviour; a single workspace entry (features unified there, `derive` added on the core side via `features = [...]` on top of `workspace = true`) keeps CVE bumps a one-line change.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 sqlx is declared once under [workspace.dependencies] and both crates inherit it with workspace = true (core adding the derive feature locally)
- [ ] #2 cargo build --all --all-features and make e2e still build the example and the proxy against one sqlx version
<!-- AC:END -->
