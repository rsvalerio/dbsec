---
id: TASK-0279
title: >-
  SEC-31: SessionPortals::parse overwrites a named statement PostgreSQL refuses
  to replace, so a later Bind of that name seals the wrong parameters
status: Triage
assignee: []
created_date: '2026-08-22 00:46'
labels:
  - code-review-rust
  - security
dependencies: []
modified_files:
  - crates/proxy/src/portal.rs
  - crates/proxy/src/encrypt/frame.rs
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/portal.rs:409`

**What**: crates/proxy/src/portal.rs:409-424: `parse` unconditionally replaces any existing entry under `statement` with a fresh id, new `ParamTransforms` and `described: None`. PostgreSQL only does that for the unnamed statement (""); a Parse of a *named* statement that already exists fails with `prepared statement "s" already exists` (exec_parse_message -> StorePreparedStatement(allow_dup=false)) and keeps the old statement. The rewriter (frame.rs:158) calls `parse` before the Parse is forwarded and never reconciles with the backend's ErrorResponse, so after the batch's Sync the proxy's map describes the *new* SQL while the backend still holds the *old* one. Every later Bind of that name is transformed against the wrong statement: if the replacement SQL has no protected placeholders (`SELECT $1::text`) while the original was `INSERT INTO users (ssn) VALUES ($1)`, `bind` returns empty transforms, the Bind is relayed verbatim, and the backend executes the original INSERT with the plaintext SSN. The same entry is `described: None`, so the read path reports `Undescribed` for a statement the backend did describe. `bind` (portal.rs:432) has the same replace-on-conflict for named portals, but portals die with the (aborted) transaction so the exposure there is negligible.

**Why it matters**: A client (buggy or hostile) can route a plaintext value into a protected column through the extended protocol without any refusal, which is exactly the silent write-path degradation the SEC-31 tasks exist to close, and can also strip a sealed Bind of the transforms the backend's real statement needs. It also desynchronises described positions for that name for the rest of the session.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Parse of a non-empty statement name that already exists in the session map leaves the existing entry (id, params, described) untouched — mirroring the backend, which will error and keep the old statement; only the unnamed statement "" is replaced
- [ ] #2 A unit test in portal.rs: parse("s", protected params), parse("s", empty params) again without Close, then bind("", "s") still returns the protected params and row_source for an Execute still uses the first description
- [ ] #3 Optionally the rewriter refuses the duplicate Parse itself with the backend's wording; either way the proxy's state must match what the backend actually holds after the batch's ReadyForQuery
<!-- AC:END -->
