---
id: TASK-0250
title: >-
  READ-4: start's doc paragraph is attached to print_help, so the help-writer's
  doc opens with 'Everything that happens before the runtime exists'
status: Triage
assignee: []
created_date: '2026-08-21 19:54'
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
**File**: `crates/proxy/src/main.rs:529`

**What**:
```rust
/// Everything that happens before the runtime exists: the command line, the
/// process hardening that has to be in place before any key material is read,
/// and the config itself.
/// Writes the help text, treating a closed pipe as success.
...
fn print_help(out: &mut impl Write) -> ExitCode {
```
The first three lines describe `start` (main.rs:560), which now has no doc comment; `print_help` was inserted between the comment and its function. Same mechanism as closed TASK-0171 but a different, production-code site not covered by that task's AC.

**Why it matters**: `start` decides the help vs hardening vs config order, and its rationale is rendered as the first paragraph of `print_help` in cargo doc and on hover.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The three-line paragraph sits immediately above fn start
- [ ] #2 print_help's doc begins with 'Writes the help text...'
<!-- AC:END -->
