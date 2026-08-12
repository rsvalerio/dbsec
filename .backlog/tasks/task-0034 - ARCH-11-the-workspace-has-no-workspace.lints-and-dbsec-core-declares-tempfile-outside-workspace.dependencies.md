---
id: TASK-0034
title: >-
  ARCH-11: the workspace has no [workspace.lints], and dbsec-core declares
  tempfile outside [workspace.dependencies]
status: Done
assignee:
  - TASK-0057
created_date: '2026-08-11 19:26'
updated_date: '2026-08-12 10:42'
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
- [x] #1 The root Cargo.toml defines [workspace.lints] and both member crates inherit it with [lints] workspace = true
- [x] #2 unsafe_code is forbidden (or denied with a documented exception) across the workspace
- [x] #3 tempfile is declared in [workspace.dependencies] and inherited by both crates that use it
- [x] #4 A local cargo clippy run produces the same lint set as CI, with no lint policy passed only as a CI flag
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
- Root `Cargo.toml` gains `[workspace.lints.rust]` and `[workspace.lints.clippy]`; both `crates/core` and `crates/proxy` inherit with `[lints] workspace = true`.
- `unsafe_code = "forbid"` (not `deny`, so no module can re-allow it). `fuzz/` is `exclude`d from the workspace and cannot inherit — libfuzzer's `fuzz_target!` expands to an `extern "C"` entry point that is unsafe by construction. That is recorded as a comment next to the lint.
- `tempfile = "3"` moved into `[workspace.dependencies]`; `crates/core` and `crates/proxy` both inherit it with `{ workspace = true }`.
- Lint set actually adopted: `unsafe_code` forbid; `unused_qualifications`, `unused_lifetimes`, `unused_macro_rules` deny; `clippy::all` deny (priority -1) plus `dbg_macro`, `todo`, `unimplemented`, `mem_forget` deny. Levels are `deny` rather than `warn` deliberately — the shared forge workflow runs clippy with `-D warnings`, so a `warn` here would pass locally and fail in CI, which is the exact divergence AC #4 is about.
- `clippy::pedantic` and `missing_docs` were evaluated and left out rather than enabled-and-blanket-allowed; adopting them is a separate piece of work, not a config line.
- Adopting `unused_qualifications` surfaced two real hits in `crates/proxy/src/session.rs` (`std::sync::Arc::new` where `Arc` is already imported, in the `#[cfg(test)]` module). Both fixed in this wave.
- Residual gap, documented in the manifest comment: CI's `-D warnings` also escalates rustc's own default-warn lints, which cannot be enumerated in a manifest. `warnings = "deny"` was considered and rejected — it would turn every mid-edit unused import into a hard local build error. The *lint set* is now entirely in the manifest; only that blanket escalation remains a CI flag.

Verified with `ops verify` (7/7: fmt, clippy `--all-targets -D warnings`, build, whitespace, EOF, JSON, YAML) and `cargo test --all --all-features`.
<!-- SECTION:NOTES:END -->
