---
id: TASK-0190
title: >-
  CI: the forge-sync job is red because the CONTRIBUTING.md waiver no longer
  matches forge@v1
status: Triage
assignee: []
created_date: '2026-08-19 13:06'
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
- [ ] #1 scripts/forge-sync-check.sh exits 0, with any genuinely shared upstream change taken into CONTRIBUTING.md rather than waived
<!-- AC:END -->
