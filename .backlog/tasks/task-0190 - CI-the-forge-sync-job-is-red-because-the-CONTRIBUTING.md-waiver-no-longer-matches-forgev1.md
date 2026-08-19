---
id: TASK-0190
title: >-
  CI: the forge-sync job is red because the CONTRIBUTING.md waiver no longer
  matches forge@v1
status: Done
assignee: []
created_date: '2026-08-19 13:06'
updated_date: '2026-08-19 13:18'
labels:
  - code-review-rust
  - ci
dependencies: []
modified_files:
  - .forge-sync/waivers/CONTRIBUTING.md.patch
  - CONTRIBUTING.md
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `.forge-sync/waivers/CONTRIBUTING.md.patch`

**What**: `./scripts/forge-sync-check.sh` exits 1, so the `forge-sync` job in
`.github/workflows/ci.yml` fails. The reported drift is exactly the content the
waiver already covers — filling in `{{REPO}}`, the development-setup section and
the project-layout section — but the recorded patch opens with `@@ -1,24` while
the check now produces `@@ -1,26`. The upstream `forge/templates/CONTRIBUTING.md`
gained two lines at `v1` after the waiver was recorded, so the stored patch no
longer matches and every run reports the deliberate divergence as drift.

The fix is most likely a re-record:
`FORGE_SYNC_REASON='...' ./scripts/forge-sync-check.sh --update`. Confirm first
that the two new upstream lines are in a *shared* section rather than a
project-specific one — if they are shared, this repo's copy should take them
before the waiver is re-recorded, which is the case the manifest comment says the
check exists to catch.

**Why it matters**: a permanently red CI job stops being read. This one is the
only thing that notices a forge-side edit to a shared section, so while it is red
that detection is off — and a genuine drift would look exactly like today's noise.

**Origin**: noticed during TASK-0189 while adding the `cargo doc` CI gate. It
predates that work: the check also exits 1 at 562289d, this session's starting
commit.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 scripts/forge-sync-check.sh exits 0, with any genuinely shared upstream change taken into CONTRIBUTING.md rather than waived
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Root cause was not an upstream change. Verified by reverse-applying the recorded waiver to this repo's `CONTRIBUTING.md`: the result is byte-identical to `templates/CONTRIBUTING.md@v1` as it stands today, so forge had not moved, and `CONTRIBUTING.md` and its waiver are both unchanged since 49639ad recorded them.

What differed was the *patch text*. The check compared the stored waiver against a freshly generated `diff -u`, and two diff implementations describe the same change with different hunk boundaries — BSD groups the title line and the following comment block differently from GNU, giving `@@ -1,24` where the other gives `@@ -1,26`. So the comparison passed only on whichever platform recorded the waiver and failed everywhere else.

Fixed by comparing the waiver's *effect* rather than its text: the canonical file plus the recorded patch (`patch --fuzz=0`) must reproduce this repo's copy byte for byte. That is implementation-independent and keeps the detection the check exists for — a forge-side edit inside a waived region makes the patch fail to apply, and one outside it makes the result differ from the local copy. Both paths were exercised, and the drift report now shows only what differs beyond the recorded divergence instead of dumping the whole patch.

No re-record was needed, so the waiver still carries its original reason.

Correction to this task's own description: the `forge config drift` **CI job was never failing**. It has passed on every recent `main` run, and it passed on this branch too. The task was filed from a local `./scripts/forge-sync-check.sh` exit code without checking the CI job, and the description's "the forge-sync job in .github/workflows/ci.yml fails" and "a permanently red CI job" are wrong.

The real scope: the check failed only where the local `diff` differs from the one that recorded the waiver — macOS/BSD here, GNU in CI. So `make forge-sync` was red for anyone on macOS and green in CI, for the same tree.

The fix and the reasoning below are unaffected, and it is still worth having: a check that is permanently red locally stops being run before a push, and it is the only thing that notices a forge-side edit to a shared section.
<!-- SECTION:NOTES:END -->
