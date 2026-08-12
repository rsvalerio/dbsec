---
id: TASK-0004
title: >-
  forge lint configs (deny, clippy, rustfmt) are hand-copied with nothing
  detecting drift
status: Done
assignee:
  - TASK-0057
created_date: '2026-08-11 20:40'
updated_date: '2026-08-12 10:42'
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
- [x] #1 CI fails when deny.toml, clippy.toml or rustfmt.toml differs from the forge tag the workflows are pinned to
- [x] #2 The check names the drifting file and shows the diff, so the fix is a copy-paste
- [x] #3 CONTRIBUTING.md is covered by the same check, or its do-not-edit-in-place claim is dropped
- [x] #4 The check is skippable with a recorded reason for deliberate divergence
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Implemented as `scripts/forge-sync-check.sh` + `.forge-sync/manifest`, wired into CI as the `forge-sync` job in `ci.yml` and into `make forge-sync` / `make pre-release`.

- The forge ref is read out of `.github/workflows/*.yml` rather than configured separately, so the check always compares against the tag the reusable workflows are pinned to and follows a pin bump automatically. It fails if the workflows disagree on the ref.
- Covered files: `clippy.toml`, `deny.toml`, `rustfmt.toml` (from `forge/config`) and `CONTRIBUTING.md` (from `forge/templates`) — AC #3 is satisfied by coverage rather than by dropping the claim.
- Deliberate divergence is recorded as the expected *diff* under `.forge-sync/waivers/<file>.patch` with a mandatory `# reason:` header, not as a whole-file exemption: a later change on the forge side still fails the check. That matters most for `deny.toml`, where a blanket skip would hide an advisory-policy update.
- One divergence exists today and is now recorded: `deny.toml` adds the `ring` `license-files` hash that the forge baseline omits.
- Both sides are compared with trailing whitespace stripped, because `ops verify` strips it repo-wide and would otherwise eat the blank context lines inside a recorded patch.
- Failure path verified by hand: an added line in `clippy.toml` produced a run naming the file and printing the unified diff, exit 1.

`README.md` and `plans/PLAN.md` updated: "keep in sync" is now a checked claim.
<!-- SECTION:NOTES:END -->
