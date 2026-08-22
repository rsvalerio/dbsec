---
id: TASK-0244
title: >-
  FN-1: relay is a 113-line function mixing header read, shutdown select, bound
  check, body read, four write arms and buffer trimming
status: Triage
assignee: []
created_date: '2026-08-21 19:54'
labels:
  - code-review-rust
  - complexity
dependencies: []
modified_files:
  - crates/proxy/src/session.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/session.rs:586-699`

**What**: `async fn relay` spans lines 586-699; the `match transform(...)` at 642 alone runs 50 lines across four arms, each with its own lock/write/log sequence.

**Why it matters**: the write arms are where the TLS flush fix has to be applied consistently, and today three of four arms already differ in whether they flush/shutdown; a `write_frame`/`read_frame` split would put the per-arm I/O contract in one place.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The frame read (header + bound + body) and frame write (header + body + flush) are extracted into named helpers and relay is <= 50 lines
- [ ] #2 Existing relay tests pass unchanged
<!-- AC:END -->
