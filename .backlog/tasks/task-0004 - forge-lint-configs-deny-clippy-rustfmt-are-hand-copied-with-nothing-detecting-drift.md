---
id: TASK-0004
title: >-
  forge lint configs (deny, clippy, rustfmt) are hand-copied with nothing
  detecting drift
status: To Do
assignee:
  - TASK-0057
created_date: '2026-08-11 20:40'
updated_date: '2026-08-11 22:42'
labels:
  - ci
  - maintenance
dependencies: []
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `deny.toml`, `clippy.toml`, `rustfmt.toml`, `plans/PLAN.md:114-116`, `README.md`

**What**: All three lint configs are described as "copies of forge's canonical versions", and PLAN.md instructs "keep in sync". Nothing checks this. `ci.yml` and `bump.yml` are thin wrappers around `rsvalerio/forge` reusable workflows pinned at `@v1`, so forge's *workflows* update automatically — but its *configs* only move when someone remembers to re-copy them by hand.

`CONTRIBUTING.md:7` has the same shape: it points at `forge/templates/CONTRIBUTING.md` and asks that the file not be edited in place. Also unenforced.

**Why it matters**: The failure is silent and one-directional. forge tightens a clippy lint or adds a RUSTSEC advisory exception, dbsec's copy stays stale, and dbsec quietly runs weaker gates than the org standard believes it does — while `make check` stays green and everything looks fine. Drift in `deny.toml` specifically means advisory coverage differs from the canonical policy, which is the one config where a silent gap has security consequences.

A CI step that diffs the local copies against the pinned forge tag and fails on mismatch costs very little and turns a memory-dependent process into a checked one.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 CI fails when deny.toml, clippy.toml or rustfmt.toml differs from the forge tag the workflows are pinned to
- [ ] #2 The check names the drifting file and shows the diff, so the fix is a copy-paste
- [ ] #3 CONTRIBUTING.md is covered by the same check, or its do-not-edit-in-place claim is dropped
- [ ] #4 The check is skippable with a recorded reason for deliberate divergence
<!-- AC:END -->
