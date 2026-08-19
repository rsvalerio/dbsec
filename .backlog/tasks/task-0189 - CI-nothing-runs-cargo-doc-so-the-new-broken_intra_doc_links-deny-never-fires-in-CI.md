---
id: TASK-0189
title: >-
  CI: nothing runs cargo doc, so the new broken_intra_doc_links = deny never
  fires in CI
status: Done
assignee: []
created_date: '2026-08-19 10:40'
updated_date: '2026-08-19 13:06'
labels:
  - code-review-rust
  - architecture
dependencies: []
modified_files:
  - Cargo.toml
  - .github/workflows/ci.yml
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `Cargo.toml:107`

**What**: TASK-0157 added `[workspace.lints.rustdoc] broken_intra_doc_links = "deny"` so that
moving an item between modules fails the build instead of silently unlinking the prose. A
rustdoc lint only fires during a documentation build, and nothing in this repo runs one:
`ops verify` is fmt/clippy/build/whitespace/json/yaml, `make` has no doc target, and
`.github/workflows/ci.yml` delegates to the shared `rsvalerio/forge` `rust-ci` workflow.
Either that workflow already runs `cargo doc` — in which case this is a no-op and the task
closes — or the deny is enforced only by whoever happens to run `cargo doc` locally.

**Why it matters**: the point of the lint was to make the breakage visible automatically.
The 16 links TASK-0157 repaired had accumulated precisely because nothing checked. Without
a gate that runs it, the same drift resumes on the next module move.

**Origin**: discovered during TASK-0180 while fixing TASK-0157.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 cargo doc --no-deps --document-private-items runs in CI, or the forge rust-ci workflow is confirmed to already run it and this task is closed with that finding recorded
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Resolved by the first branch of AC#1, not the second: the forge `rust-ci` workflow does **not** run `cargo doc`. Fetched `rsvalerio/forge/.github/workflows/rust-ci.yml@v1` and its jobs are Format (`cargo fmt --all --check`), Check, Lint (`cargo clippy`), Build, Test and Deps (`cargo deny check`) — six compiler-lint gates, no documentation build. So `broken_intra_doc_links = "deny"` was enforced only by whoever happened to run `cargo doc` locally.

Added a `docs` job to `.github/workflows/ci.yml` running `cargo doc --no-deps --document-private-items --all-features`, and a matching `make docs` target so the local gate and CI agree. `ops verify` was not extended because `ops` is a compiled binary whose gates are derived from the detected stack, not configured from this repo.

Verified the gate actually fires: a deliberate `[\`does::not::Exist\`]` link added to `crates/core/src/lib.rs` fails the build with `error: unresolved link to \`does::not::Exist\`` / `error: could not document \`dbsec-core\``, and passes once removed.
<!-- SECTION:NOTES:END -->
