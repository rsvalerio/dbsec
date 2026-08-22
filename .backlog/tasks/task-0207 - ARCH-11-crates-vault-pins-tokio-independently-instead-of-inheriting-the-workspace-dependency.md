---
id: TASK-0207
title: >-
  ARCH-11: crates/vault pins tokio independently instead of inheriting the
  workspace dependency
status: Triage
assignee: []
created_date: '2026-08-21 19:36'
labels:
  - code-review-rust
  - architecture
dependencies: []
modified_files:
  - crates/vault/Cargo.toml
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/vault/Cargo.toml:25`

**What**: `tokio = { version = "1", default-features = false, features = ["rt", "rt-multi-thread", "time", "macros"] }` is declared directly, while `[workspace.dependencies]` already defines `tokio` (with a superset of these features) and every other dependency in this crate uses `workspace = true`. The comment explains the feature choice but not why the version is not inherited; `workspace = true` accepts an additional `features = [...]` list, and `default-features = false` on a member has no effect on a workspace dep anyway (features unify additively across the workspace build).

**Why it matters**: ARCH-11: a CVE bump for tokio now has two places to edit, and `cargo update`/Dependabot will drift them independently. The intent (a minimal feature set for the published crate) is still expressible via `features` on the inherited dependency.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 crates/vault/Cargo.toml declares tokio = { workspace = true, features = [...] } (or the workspace tokio is split so the vault feature set is declared once)
- [ ] #2 cargo build -p dbsec-vault and cargo test -p dbsec-vault pass
<!-- AC:END -->
