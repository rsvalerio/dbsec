---
id: TASK-0189
title: >-
  CI: nothing runs cargo doc, so the new broken_intra_doc_links = deny never
  fires in CI
status: Triage
assignee: []
created_date: '2026-08-19 10:40'
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
- [ ] #1 cargo doc --no-deps --document-private-items runs in CI, or the forge rust-ci workflow is confirmed to already run it and this task is closed with that finding recorded
<!-- AC:END -->
