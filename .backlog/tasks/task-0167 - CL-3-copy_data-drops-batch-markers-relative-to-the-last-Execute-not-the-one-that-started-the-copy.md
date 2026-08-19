---
id: TASK-0167
title: >-
  CL-3: copy_data drops batch markers relative to the last Execute, not the one
  that started the copy
status: Triage
assignee: []
created_date: '2026-08-19 08:32'
labels:
  - code-review-rust
  - protocol
dependencies: []
modified_files:
  - crates/proxy/src/portal.rs
  - crates/proxy/src/session.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/portal.rs:432`

**What**: `copy_data` locates the Execute with `pending.iter().rposition(...)` and pops trailing
`Pending::Batch` entries after it. The comment says "only markers queued after the Execute that
started the copy are dropped", but `rposition` finds the *last* Execute in the queue, which in a
pipelined session is not the copy's. A client that pipelines a second batch behind the copy has
that batch's marker dropped instead.

**Why it matters**: the stated invariant and the code disagree. A wrongly dropped Batch marker
leaves the queue one response behind, which the module docs identify as surfacing as
`Error::UndescribedRow` — a client-driven refusal of its own session. Fail-closed, and only
reachable with an unusual pipeline shape.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The Execute that started the copy is identified explicitly rather than inferred as the last one
- [ ] #2 A test pipelines a batch behind a COPY ... FROM STDIN Execute and asserts the second batch's marker survives
<!-- AC:END -->
