---
id: TASK-0171
title: 'READ-4: a doc comment was detached from its test by the closed-pipe fix'
status: Triage
assignee: []
created_date: '2026-08-19 08:32'
labels:
  - code-review-rust
  - readability
dependencies: []
modified_files:
  - crates/proxy/src/main.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/main.rs:844`

**What**: the comment at `main.rs:844-847` ("TASK-0130: asking what the flags are is not a usage
error. Both spellings are recognised...") describes
`help_is_a_startup_outcome_rather_than_a_usage_error`, which now carries no doc at all.
`a_closed_pipe_makes_help_succeed_rather_than_fail` was inserted *above* the existing comment
rather than above the existing test, so the reader of the closed-pipe test is told about
`Error::Usage` and both `--help` spellings, which it does not check.

**Why it matters**: trivially fixable, and exactly the class of drift a split review looks for.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The TASK-0130 paragraph moves to immediately above help_is_a_startup_outcome_rather_than_a_usage_error
- [ ] #2 a_closed_pipe_makes_help_succeed_rather_than_fail keeps only its own doc lines
<!-- AC:END -->
