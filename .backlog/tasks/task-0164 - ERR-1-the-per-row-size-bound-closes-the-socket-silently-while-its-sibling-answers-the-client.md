---
id: TASK-0164
title: >-
  ERR-1: the per-row size bound closes the socket silently while its sibling
  answers the client
status: Triage
assignee: []
created_date: '2026-08-19 08:31'
labels:
  - code-review-rust
  - error-handling
dependencies: []
modified_files:
  - crates/proxy/src/rows.rs
  - crates/proxy/src/main.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/rows.rs:422`

**What**: `decrypt_row` enforces two bounds. `Bounds::max_value` raises
`Error::ProtectedValueTooLarge`, which `is_refusal` lists, so the client gets an ErrorResponse
before the close. `Bounds::max_body` raises `Error::FrameTooLarge`, which `is_refusal` does
not list, so `on_frame` returns `Err` and the relay drops the connection with nothing sent.
Both are the same policy — how much transient memory one row may cost.

**Why it matters**: diagnosability only (both fail closed), but the two halves of one bound
behave differently for no stated reason, and the silent half is the one an operator hits as
"random disconnects". The module's own rationale for the refusal path is that dropping the
socket silently "gave the client Closed rather than a DbError, so a policy refusal read as a
network fault".
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Either FrameTooLarge from decrypt_row is routed through refuse, or rows.rs documents why the two bounds differ
- [ ] #2 The refusal-vs-fatal classification is asserted in a test alongside the frame-ceiling test
<!-- AC:END -->
