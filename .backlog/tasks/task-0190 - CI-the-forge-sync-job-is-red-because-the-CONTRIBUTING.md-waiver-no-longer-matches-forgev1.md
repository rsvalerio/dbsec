---
id: TASK-0190
title: >-
  CI: the forge-sync waiver comparison is diff-implementation-dependent, so the
  check fails on macOS
status: Done
assignee: []
created_date: '2026-08-19 13:06'
updated_date: '2026-08-19 14:48'
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
**File**: `scripts/forge-sync-check.sh`

**What**: `./scripts/forge-sync-check.sh` exits 1 for `CONTRIBUTING.md` on macOS
while the identical tree passes in CI, so `make forge-sync` is red for any
developer on a BSD-diff platform and green on the GNU-diff runner.

The check compared the stored waiver's *text* against a freshly generated
`diff -u`. Two diff implementations describe the same change with different hunk
boundaries — BSD groups the title line and the comment block below it
differently from GNU, producing `@@ -1,26` where the other produces `@@ -1,24` —
so the comparison could only pass on whichever platform's diff recorded the
waiver. GNU recorded this one.

Nothing was actually out of sync: reverse-applying the waiver to this repo's
`CONTRIBUTING.md` reproduces `templates/CONTRIBUTING.md@v1` byte for byte, and
both files are unchanged since 49639ad recorded them. So there was no upstream
change to take in and no re-record to make.

**Why it matters**: a check that is permanently red on a developer's machine
stops being run before a push, and this is the only thing that notices a
forge-side edit to a shared section — `deny.toml`'s advisory policy included,
where a missed update is a security gap rather than a style one.

**Origin**: noticed during TASK-0189 while adding the `cargo doc` CI gate.

**Note on this record**: it was originally filed claiming the *CI job* was
failing, which was never true — see the correction and the run identifiers in
the notes. The title and this description have been rewritten; the filename
still carries the original slug.
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

Dates and identifiers for the claims above, recorded 2026-08-19 so they stay checkable after archival:

- `forge config drift` on `main`: passing. CI run 32236895904 (562289d, this session's starting commit), job 96018783787 — plus runs 32233197832 (e4e9801) and 32187666438 (5bf0d0b), all `success`.
- The same job on PR #17 before any fix: run 32256722681, job 96080023726, `success`.
- `./scripts/forge-sync-check.sh` run locally on macOS (Apple diff, based on FreeBSD diff) at 562289d and at every later commit of this branch: exit 1.
- `templates/CONTRIBUTING.md@v1` fetched 2026-08-19 is byte-identical to the file reconstructed by reverse-applying `.forge-sync/waivers/CONTRIBUTING.md.patch` to this repo's `CONTRIBUTING.md`, so the forge side had not moved.
- `CONTRIBUTING.md` and its waiver are unchanged since 49639ad recorded them.

The title has been corrected too: it said the CI job was red, which was never true. See the correction note above.
<!-- SECTION:NOTES:END -->
