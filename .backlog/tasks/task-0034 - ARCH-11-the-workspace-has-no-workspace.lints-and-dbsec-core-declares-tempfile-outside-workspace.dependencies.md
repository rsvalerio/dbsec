---
id: TASK-0034
title: >-
  ARCH-11: the workspace has no [workspace.lints], and dbsec-core declares
  tempfile outside [workspace.dependencies]
status: To Do
assignee:
  - TASK-0057
created_date: '2026-08-11 19:26'
updated_date: '2026-08-11 22:42'
labels:
  - code-review-rust
  - architecture
dependencies: []
modified_files:
  - Cargo.toml
  - crates/core/Cargo.toml
  - crates/proxy/Cargo.toml
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `Cargo.toml:1-10`, `crates/core/Cargo.toml:24`

**What**: Two halves of the same rule.

1. Neither the root `Cargo.toml` nor either member declares lints. There is no `[workspace.lints]` table and no `[lints] workspace = true` in `crates/core/Cargo.toml` or `crates/proxy/Cargo.toml`. Lint policy therefore lives entirely in whatever flags CI passes to `cargo clippy` — `clippy.toml` configures thresholds for lints that are enabled, but it cannot enable any. Nothing makes a local `cargo clippy` agree with CI, and nothing denies `unsafe_code`.

2. `crates/core/Cargo.toml:24` declares `tempfile = "3"` directly while every other dependency in the file, including the other dev-dependency `proptest`, uses `{ workspace = true }`. `tempfile` is also used by `crates/proxy/tests/common/mod.rs`, so the version is now stated in two places that can drift.

**Why it matters**: For this crate the missing lint config is more than tidiness. `#![forbid(unsafe_code)]` — or `unsafe_code = "forbid"` in `[workspace.lints.rust]` — is a one-line, permanent, machine-checked statement that a field-level encryption library contains no unsafe code. That is a claim worth being able to make to an auditor, and right now nothing prevents an `unsafe` block from landing. The same table is where `clippy::pedantic`, `missing_docs` for the public API, and the arithmetic lints relevant to TASK-0032 would go, applied identically to both crates and to every future member.

The `tempfile` half is minor on its own but is the exact drift ARCH-11 describes: two crates, one dependency, two independent version statements.

Distinct from TASK-0004, which is about the shared `deny.toml`/`clippy.toml`/`rustfmt.toml` files being hand-copied between repos with no drift detection. This is about lint policy inside this workspace's `Cargo.toml`, which those files cannot express.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The root Cargo.toml defines [workspace.lints] and both member crates inherit it with [lints] workspace = true
- [ ] #2 unsafe_code is forbidden (or denied with a documented exception) across the workspace
- [ ] #3 tempfile is declared in [workspace.dependencies] and inherited by both crates that use it
- [ ] #4 A local cargo clippy run produces the same lint set as CI, with no lint policy passed only as a CI flag
<!-- AC:END -->
