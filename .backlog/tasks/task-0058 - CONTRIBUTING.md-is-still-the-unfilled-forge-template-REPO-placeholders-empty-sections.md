---
id: TASK-0058
title: >-
  CONTRIBUTING.md is still the unfilled forge template ({{REPO}} placeholders,
  empty sections)
status: Triage
assignee: []
created_date: '2026-08-12 10:40'
labels:
  - code-review-rust
  - docs
dependencies: []
modified_files:
  - CONTRIBUTING.md
  - .forge-sync/manifest
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `CONTRIBUTING.md`

**What**: The file was copied from `forge/templates/CONTRIBUTING.md` and never adapted. It still reads `# Contributing to {{REPO}}`, still carries the template's own instruction comment ("Copy into the consuming repository, replace {{REPO}}, and fill in ..."), and both project-specific sections are empty placeholders: "Development setup" clones `https://github.com/rsvalerio/{{REPO}}`, and "Project layout" is a bare HTML comment with no crate table.

**Why it matters**: This is the first file a new contributor opens, and it currently tells them to clone a repository that does not exist and shows them template scaffolding instead of dbsec's layout. It also misses the two things a contributor to this repo actually needs: `make check` / `ops verify` as the gate entry point, and the `crates/core` vs `crates/proxy` split.

Note the interaction with the new drift check: `CONTRIBUTING.md` is listed in `.forge-sync/manifest`, so filling it in will make `scripts/forge-sync-check.sh` fail until the divergence is recorded with `FORGE_SYNC_REASON='...' ./scripts/forge-sync-check.sh --update`. That is the intended workflow — a per-repo CONTRIBUTING.md is expected to diverge from the shared template — but the waiver patch will be large. Consider narrowing the manifest entry for this file to the shared sections instead, or dropping it from the manifest and keeping only the three lint configs under exact-match drift detection.

**Origin**: discovered during TASK-0057 while fixing TASK-0004 (the drift check covers this file, which is how the unfilled state surfaced).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 CONTRIBUTING.md names dbsec instead of {{REPO}} and the template's copy-me comment is gone
- [ ] #2 Development setup and Project layout are filled in for this repo (toolchain, make targets, crates/core vs crates/proxy)
- [ ] #3 scripts/forge-sync-check.sh still passes, either via a recorded waiver or by narrowing what the manifest checks for this file
<!-- AC:END -->
