---
id: TASK-0172
title: >-
  TEST-11: help_survives_a_reader_that_closes_the_pipe asserts head's exit code,
  not dbsec's
status: Triage
assignee: []
created_date: '2026-08-19 08:32'
labels:
  - code-review-rust
  - test-quality
dependencies: []
modified_files:
  - crates/proxy/tests/cli.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/tests/cli.rs:279`

**What**: the test runs `sh -c "$dbsec --help | head -1"` and asserts
`output.status.code() == Some(0)`. POSIX shells report the *last* pipeline stage's status, so
that is `head`'s, which is 0 regardless of what `dbsec` did — the assertion cannot fail for the
reason the test exists. The remaining checks (stdout carries the usage line, stderr contains
neither `panicked` nor `failed printing`) are the real ones, and the doc comment does
acknowledge the limitation.

**Why it matters**: a reader scanning for the closed-pipe exit-code guarantee finds an
`assert_eq!` on an exit code and reasonably assumes it is pinned here; it is pinned only in the
unit test.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Either drop the exit-code assertion, or use set -o pipefail / PIPESTATUS so the asserted code is dbsec's
<!-- AC:END -->
